'use strict';

require('dotenv').config();

const config = {
    port: process.env.PORT || 3000,
    sessionKey: 'Authorization',
    blockingTime: 2 * 60 * 1000,
    timeRangeToCheck: 5000,
    domain: process.env.DOMAIN || 'dev-ciqz1vdq1irife3n.us.auth0.com',
    clientId: process.env.CLIENT_ID || 'mdfALuYL914gp5lqPsoOWaIgh8gtMyXq',
    clientSecret: process.env.CLIENT_SECRET || 'wRBB9kua92GDaDTNXsLPhUMSaKKwcu7UCYCtVvEIsVopLLBLGJzosBeWgAU-JEDx',
    audience: process.env.AUDIENCE || 'https://dev-ciqz1vdq1irife3n.us.auth0.com/api/v2/',
}

module.exports = {
    config
}
