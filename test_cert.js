const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch({ headless: false });
  const context = await browser.newContext({
    ignoreHTTPSErrors: false // Don't ignore - we want to test if cert is trusted
  });
  const page = await context.newPage();

  try {
    console.log('Navigating to https://localhost:8443/test.html...');
    await page.goto('https://localhost:8443/test.html');

    const title = await page.textContent('h1');
    console.log('✅ Page loaded successfully!');
    console.log('Title:', title);

    const text = await page.textContent('p');
    console.log('Content:', text);

    // Take screenshot
    await page.screenshot({ path: 'test_success.png' });
    console.log('📸 Screenshot saved to test_success.png');

    console.log('\n🎉 Certificate is working and trusted!');
  } catch (error) {
    console.error('❌ Error:', error.message);
  }

  await browser.close();
})();
