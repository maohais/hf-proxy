const MAX_RETRIES = 3;
const RETRY_DELAY_MS = 500;
const EXPIRATION_BUFFER_SECONDS = 60;
const LOCK_TTL = 10; // 秒

// JWT 解析工具
const JWT = {
  parse: (token) => {
    try {
      const base64Url = token.split('.')[1];
      const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
      const jsonPayload = atob(base64.padEnd(base64.length + (4 - base64.length % 4) % 4, '='));
      return JSON.parse(jsonPayload);
    } catch {
      return { exp: Math.floor(Date.now()/1000) + 3600 };
    }
  }
};

// Cookie 处理工具
const Cookie = {
  parse: (header) => {
    const map = new Map();
    (header || '').split(';').forEach(c => {
      const [k, v] = c.trim().split('=');
      if (k) map.set(k, v?.trim());
    });
    return map;
  },
  stringify: (map) => {
    return Array.from(map).map(([k, v]) => `${k}=${v}`).join('; ');
  }
};

async function getJwtToken(HF_SPACE_NAME, HF_TOKEN, HF_SPACE_USER, forceRefresh = false) {
  // 动态生成存储键名
  const JWT_VALUE_KEY = `${HF_SPACE_NAME}_jwt_value`;
  const JWT_EXPIRATION_KEY = `${HF_SPACE_NAME}_jwt_expiration`;
  const LOCK_KEY = `${HF_SPACE_NAME}_jwt_refresh_lock`;

  const now = Date.now() / 1000;

  // 检查缓存
  const [cachedToken, cachedExpiration] = await Promise.all([
    my_kv.get(JWT_VALUE_KEY),
    my_kv.get(JWT_EXPIRATION_KEY)
  ]);

  if (cachedToken && cachedExpiration && 
      parseFloat(cachedExpiration) > now + EXPIRATION_BUFFER_SECONDS && 
      !forceRefresh) {
    return cachedToken;
  }

  // 带锁刷新逻辑
  const refreshWithLock = async () => {
    let lock = await my_kv.get(LOCK_KEY);
    if (lock) {
      await new Promise(r => setTimeout(r, 100));
      return refreshWithLock();
    }

    try {
      await my_kv.put(LOCK_KEY, '1', { expirationTtl: LOCK_TTL });
      
      // 再次检查缓存（防止并发时重复刷新）
      const [recheckToken, recheckExp] = await Promise.all([
        my_kv.get(JWT_VALUE_KEY),
        my_kv.get(JWT_EXPIRATION_KEY)
      ]);
      
      if (recheckToken && recheckExp && 
          parseFloat(recheckExp) > now + EXPIRATION_BUFFER_SECONDS && 
          !forceRefresh) {
        return recheckToken;
      }

      // 获取新 Token
      const HF_API_URL = `https://huggingface.co/api/spaces/${HF_SPACE_USER}/${HF_SPACE_NAME}/jwt`;
      let response, retries = 0;

      while (retries < MAX_RETRIES) {
        try {
          response = await fetch(HF_API_URL, {
            headers: { "Authorization": `Bearer ${HF_TOKEN}` }
          });

          if (response.ok) break;

          if ([429, 500, 502, 503, 504].includes(response.status)) {
            retries++;
            await new Promise(r => setTimeout(r, RETRY_DELAY_MS));
            continue;
          }

          throw new Error(`HTTP ${response.status}: ${await response.text()}`);
        } catch (error) {
          if (++retries >= MAX_RETRIES) throw error;
          await new Promise(r => setTimeout(r, RETRY_DELAY_MS));
        }
      }

      const { token } = await response.json();
      const { exp } = JWT.parse(token);

      // 更新缓存
      await Promise.all([
        my_kv.put(JWT_VALUE_KEY, token),
        my_kv.put(JWT_EXPIRATION_KEY, exp.toString())
      ]);

      return token;
    } finally {
      await my_kv.delete(LOCK_KEY).catch(() => {});
    }
  };

  return refreshWithLock();
}

export async function onRequest({ request, env }) {
  const { HF_TOKEN, HF_SPACE_NAME, HF_SPACE_USER } = env;
  
  try {
    // 前置检查
    if (!HF_TOKEN || !HF_SPACE_NAME || !HF_SPACE_USER) {
      throw new Error('Missing required environment variables');
    }

    // 处理请求
    const url = new URL(request.url);
    url.host = `${HF_SPACE_USER}-${HF_SPACE_NAME}.hf.space`;

    // 构造新请求头
    const headers = new Headers(request.headers);
    headers.set('Host', url.host);
    headers.delete('Origin');
    headers.delete('Referer');

    // 处理 Cookies
    const cookieMap = Cookie.parse(headers.get('Cookie'));
    let token = await getJwtToken(HF_SPACE_NAME, HF_TOKEN, HF_SPACE_USER);
    cookieMap.set('spaces-jwt', token);
    headers.set('Cookie', Cookie.stringify(cookieMap));

    // 发送请求
    let response = await fetch(new Request(url, {
      method: request.method,
      headers,
      body: request.body,
      redirect: 'manual'
    }));

    // Token 过期重试
    if ([401, 403].includes(response.status)) {
      token = await getJwtToken(HF_SPACE_NAME, HF_TOKEN, HF_SPACE_USER, true);
      cookieMap.set('spaces-jwt', token);
      headers.set('Cookie', Cookie.stringify(cookieMap));
      
      response = await fetch(new Request(url, {
        method: request.method,
        headers,
        body: request.body,
        redirect: 'manual'
      }));
    }

    // 处理重定向
    const modifiedHeaders = new Headers(response.headers);
    if (modifiedHeaders.has('Location')) {
      const location = modifiedHeaders.get('Location')
        .replace('.hf.space', request.headers.get('Host'));
      modifiedHeaders.set('Location', location);
    }
    modifiedHeaders.delete('Link');

    return new Response(response.body, {
      status: response.status,
      headers: modifiedHeaders
    });

  } catch (error) {
    return new Response(error.message, { 
      status: 500,
      headers: { 'Content-Type': 'text/plain;charset=UTF-8' }
    });
  }
}
