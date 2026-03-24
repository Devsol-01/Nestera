const axios = require('axios');

const BASE_URL = 'http://localhost:3000';

async function testRateLimiting() {
  console.log('🧪 Testing Rate Limiting...\n');

  try {
    // Test 1: Normal request (should work)
    console.log('1. Testing normal request...');
    const response1 = await axios.get(`${BASE_URL}/test-throttling`);
    console.log('✅ Normal request successful:', response1.status);
    console.log('Response:', response1.data);
    console.log('');

    // Test 2: Unlimited endpoint (should always work)
    console.log('2. Testing unlimited endpoint...');
    const response2 = await axios.get(`${BASE_URL}/test-throttling/skip`);
    console.log('✅ Unlimited endpoint successful:', response2.status);
    console.log('Response:', response2.data);
    console.log('');

    // Test 3: Burst requests to trigger rate limiting
    console.log('3. Testing burst requests (may trigger rate limit)...');
    let successCount = 0;
    let rateLimitHit = false;
    
    for (let i = 1; i <= 105; i++) {
      try {
        const response = await axios.get(`${BASE_URL}/test-throttling/burst`);
        successCount++;
        if (i % 20 === 0) {
          console.log(`   Request ${i}: ✅ Success (${successCount}/${i})`);
        }
      } catch (error) {
        if (error.response && error.response.status === 429) {
          rateLimitHit = true;
          console.log(`   Request ${i}: 🚫 Rate Limited (429)`);
          console.log('   Rate limit response:', error.response.data);
          break;
        } else {
          console.log(`   Request ${i}: ❌ Error:`, error.message);
        }
      }
    }

    console.log(`\n📊 Results:`);
    console.log(`   Successful requests: ${successCount}`);
    console.log(`   Rate limit triggered: ${rateLimitHit ? '✅ Yes' : '❌ No'}`);
    
    if (rateLimitHit) {
      console.log('\n🎉 Rate limiting is working correctly!');
    } else {
      console.log('\n⚠️  Rate limit not triggered (may need more requests or different configuration)');
    }

  } catch (error) {
    if (error.code === 'ECONNREFUSED') {
      console.log('❌ Server is not running. Please start the server with: pnpm start:dev');
    } else {
      console.log('❌ Test failed:', error.message);
    }
  }
}

// Run the test
testRateLimiting();
