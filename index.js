const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const {logger} = require("./logger.js");
const {config} = require("./config");
const {auth} = require("express-oauth2-jwt-bearer");
const { checkIfBlocked } = require('./utils/history');
const { saveUnsuccessfulAttempt } = require('./utils/history');
const { registerUser } = require('./utils/user');
const { getUserDetailedInformation } = require('./utils/user');
const { refreshAccessToken } = require('./utils/auth');
const { authUserByLoginAndPassword } = require('./utils/auth');
const { getAccessToken } = require('./utils/auth');
const { verifyToken } = require('./utils/token-validation');

const userInfo = {}

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));

function retrieveToken(request) {
    const headerValue = request.get(config.sessionKey);
    if (headerValue) {
        token = headerValue.split(" ")[1];
        if (token) {
            return token;
        }
    }
    return null;
}

const checkJwt = auth({
    audience: config.audience,
    issuerBaseURL: `https://${config.domain}`,
});

app.use(async (req, res, next) => {
    let token = retrieveToken(req);
    if (token) {
        const payload = await verifyToken(token);
        if (payload) {
            const userId = payload.sub;
            const tokenValidTime = userInfo[payload.sub].expiresIn - 4 * 60 * 60 * 1000;
            if (Date.now() >= tokenValidTime) {
                token = await refreshAccessToken(userId, userInfo);
            }
            req.token = token
            req.userId = userId;
        }
    }
    next();
});

app.get('/userinfo', checkJwt, function (req, res) {
    const {token} = req;
    if (token) {
        const message = `User details:\n   name: ${userInfo[req.userId].name}\n    email: ${userInfo[req.userId].email}`;
        res.json({
            token: token,
            message: message
        });
    }
});

app.get('/', (req, res) => {
    const {token} = req;
    if (token) {
        const {userId} = req;
        return res.json({
            token: token,
            username: userInfo[userId].name
        });
    }
    res.sendFile(path.join(__dirname + '/index.html'));
});

app.get('/logout', (req, res) => {
    delete userInfo[req.userId];
    res.redirect('/');
});

app.post('/api/login', async (req, res) => {
    const {login, password} = req.body;
    const authInfo = await authUserByLoginAndPassword(login, password);
    const ip = req.socket.remoteAddress;
    if (authInfo.accessToken !== undefined && !checkIfBlocked(ip)) {
        logger.info(`Successfully logged in, IP: ${ip}, user: ${login}`);
        const payload = await verifyToken(authInfo.accessToken);
        const userId = payload.sub;
        const userDetailedInfo = await getUserDetailedInformation(userId, authInfo.accessToken);
        userDetailedInfo.refreshToken = authInfo.refreshToken;
        userDetailedInfo.expiresIn = Date.now() + authInfo.expiresIn * 1000;
        userInfo[userId] = userDetailedInfo;
        return res.json({
            token: authInfo.accessToken
        });
    } else {
        saveUnsuccessfulAttempt(ip);
        logger.info(`Unsuccessful attempt to login from IP: ${ip}`);
    }
    return res.status(401).send();
});

app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname + '/signup.html'));
});

app.post('/api/signup', async (req, res) => {
    const {login, password, name, nickname} = req.body;
    const clientAccessToken = await getAccessToken();
    const result = await registerUser(clientAccessToken, login, password, name, nickname);
    if (result) {
        logger.info(`Successfully registered user with login ${login}`);
        return res.json({redirect: '/'});
    }
    return res.status(500).send();
});


app.listen(config.port, () => {
    logger.info(`Example app listening on port ${config.port}`);
});
