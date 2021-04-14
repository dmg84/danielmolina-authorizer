const jwt = require('jsonwebtoken');
const jwtDecode = require('jwt-decode');
const COOKIE_HEADER = 'Cookie';
const COOKIE_NAME = 'sessionCookie';

exports.handler = async function (event, context, callback) {
    console.debug('Authenticating endpoint: ' + event.path);
    const jwtToken = getCookie(event.headers, COOKIE_NAME);

    if (jwtToken) {
        try {
            const userInfo = await verifyAuthenticationByToken(event, jwtToken);
            callback(null, generateUserPolicy(event, userInfo.id));
            return;
        } catch (error) {
            console.debug(`Error when jwtToken authorization. Cause: ${error}`);
        }
    }
    callback('Unauthorized');
};

const getCookie = (headers, cookieName) => {
    const cookies = getHeaderContentInsensitive(headers, COOKIE_HEADER);
    if (!cookies) return;

    const findCookie = cookieName + '=';

    for (const cookie of cookies.split(';')) {
        if (cookie.trim().startsWith(findCookie)) {
            return cookie.split('=')[1];
        }
    }

    return null;
};

const getHeaderContentInsensitive = (headers, name) => {
    const keys = Object.keys(headers);
    if (Array.isArray(keys)) {
        const matchingKeys = keys.filter((key) => key.toLowerCase() === name.toLowerCase());
        if (matchingKeys.length > 0) {
            return headers[matchingKeys[matchingKeys.length - 1]];
        }
    }
};

const verifyAuthenticationByToken = (event, token) => {
    return decodeAndVerifyToken(token.trim());
};

const decodeAndVerifyToken = (token) => {
    const tokenHeaderDecoded = jwtDecode(token, { header: true });
    if (tokenHeaderDecoded.alg === 'HS256') {
        return decodeAndVerifyTokenHS256(token);
    } else {
        return Promise.reject(`Token algorithm ${tokenHeaderDecoded.alg} not supported.`);
    }
};

const decodeAndVerifyTokenHS256 = async (token) => {
    try {
        const tokenDecoded = jwt.verify(token, process.env.SYMMETRIC_KEY);
        return Promise.resolve(tokenDecoded);
    } catch (error) {
        console.error('Error verifying the token HS256 [' + token + ']. Error: ', JSON.stringify(error));
        return Promise.reject(error);
    }
};

const generateUserPolicy = (event, userId) => {
    return generatePolicy(userId, 'Allow', event.methodArn);
};

// Help function to generate an IAM policy
const generatePolicy = (principalId, effect, resource) => {
    const authResponse = {
        principalId: principalId,
        context: {}
    };

    if (effect && resource) {
        authResponse.policyDocument = {
            Version: '2012-10-17',
            Statement: [
                {
                    Action: 'execute-api:Invoke',
                    Effect: effect,
                    Resource: resource ? resource : undefined
                }
            ]
        };
    }

    return authResponse;
};
