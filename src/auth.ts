export function getAuthKey(request: Request, sessionKey?: string): string | undefined {
    if (sessionKey) return sessionKey;
    // 先查 cookie
    const cookie = request.headers.get('Cookie');
    if (cookie) {
        const match = cookie.match(/auth-key=([^;]+)/);
        if (match) return match[1];
    }
    // 再查 Authorization header
    const authHeader = request.headers.get('Authorization');
    if (authHeader) {
        return authHeader.replace(/^Bearer\s+/, '');
    }
    return undefined;
}

// 管理 API 校验 HOME_ACCESS_KEY
/*
export function isAdminAuthenticated(request: Request, homeAccessKey: string): boolean {
    if (!homeAccessKey) return false;
    const key = getAuthKey(request);
    return key === homeAccessKey;
}
*/
export function isAdminAuthenticated(request: Request, homeAccessKey: string): boolean {
    if (!homeAccessKey) return false;
    
    // 取得客戶端傳來的 Key
    const key = getAuthKey(request);
    if (!key) return false;

    // 將環境變數中的字串以逗號拆分成陣列
    const allowedKeys = homeAccessKey.split(',').map(k => k.trim());
    
    // 檢查客戶端的 Key 是否在允許的清單中
    return allowedKeys.includes(key);
}
