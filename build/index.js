import { OAuth2Strategy } from 'remix-auth-oauth2';
export const GoogleStrategyScopeSeperator = ' ';
export const GoogleStrategyDefaultScopes = [
    'openid',
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/userinfo.email',
];
export const GoogleStrategyDefaultName = 'google';
export class GoogleStrategy extends OAuth2Strategy {
    name = GoogleStrategyDefaultName;
    accessType;
    prompt;
    includeGrantedScopes;
    hd;
    loginHint;
    userInfoURL = 'https://www.googleapis.com/oauth2/v3/userinfo';
    constructor({ clientID, clientSecret, callbackURL, scope, accessType, includeGrantedScopes, prompt, hd, loginHint, }, verify) {
        super({
            clientId: clientID,
            clientSecret,
            redirectURI: callbackURL,
            authorizationEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
            tokenEndpoint: 'https://oauth2.googleapis.com/token',
            scopes: GoogleStrategy.parseScope(scope),
        }, verify);
        this.accessType = accessType ?? 'online';
        this.includeGrantedScopes = includeGrantedScopes ?? false;
        this.prompt = prompt;
        this.hd = hd;
        this.loginHint = loginHint;
    }
    authorizationParams(params) {
        params.set('access_type', this.accessType);
        params.set('include_granted_scopes', String(this.includeGrantedScopes));
        if (this.prompt) {
            params.set('prompt', this.prompt);
        }
        if (this.hd) {
            params.set('hd', this.hd);
        }
        if (this.loginHint) {
            params.set('login_hint', this.loginHint);
        }
        return params;
    }
    async userProfile(tokens) {
        const response = await fetch(this.userInfoURL, {
            headers: {
                Authorization: `Bearer ${tokens.access_token}`,
            },
        });
        const raw = await response.json();
        const profile = {
            provider: 'google',
            id: raw.sub,
            displayName: raw.name,
            name: {
                familyName: raw.family_name,
                givenName: raw.given_name,
            },
            emails: [{ value: raw.email }],
            photos: [{ value: raw.picture }],
            _json: raw,
        };
        return profile;
    }
    // Allow users the option to pass a scope string, or typed array
    static parseScope(scope) {
        if (!scope) {
            return GoogleStrategyDefaultScopes;
        }
        else if (Array.isArray(scope)) {
            return scope;
        }
        return scope;
    }
}
