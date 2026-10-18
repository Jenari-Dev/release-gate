// Application configuration.
// FIXTURE NOTE: every credential below is FAKE and exists only to be found by scanners.
module.exports = {
  PORT: Number(process.env.PORT || 3101),
  HOST: '127.0.0.1',
  INTERNAL_PORT: 3191,

  // payment + cloud credentials (planted, FAKE)
  STRIPE_SECRET_KEY: 'sk_test_51FAKEfixtureKeyNotRealXq7Lm2Pz9Rt4Vw8Yb3',
  AWS_ACCESS_KEY_ID: 'AKIAIOSFODNN7EXAMPLE',
  AWS_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
};
