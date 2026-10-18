// Application configuration. Secrets come from the environment, never from source.
function required(name) {
  const v = process.env[name];
  if (!v) {
    console.error(`Missing required environment variable ${name}`);
    process.exit(1);
  }
  return v;
}

module.exports = {
  PORT: Number(process.env.PORT || 3102),
  HOST: '127.0.0.1',
  INTERNAL_PORT: 3192,
  STRIPE_SECRET_KEY: required('STRIPE_SECRET_KEY'),
  // comma-separated hostnames the link-preview feature may fetch
  PREVIEW_ALLOWED_HOSTS: (process.env.PREVIEW_ALLOWED_HOSTS || 'docs.example.test').split(',').map((s) => s.trim().toLowerCase()),
};
