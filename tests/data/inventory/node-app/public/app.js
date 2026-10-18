// Browser code: storage and event tracking.
localStorage.setItem('theme', 'dark');
sessionStorage.setItem('cart', JSON.stringify(items));
document.cookie = 'lang=en; max-age=31536000';
gtag('event', 'purchase', { value: 10, email: user.email });
