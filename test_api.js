const API_URL = 'http://ipcatt.top';
const API_KEY = 'Gb7c>RVbS5G~FmoDN?>^w^2!leE-jl^PDXF%,zT[/v/R>IdLx@';

/**
 * Super simple Node.js script to test our hosted Secure API Gateway.
 */
async function testGateway() {
  console.log('--- Checking API Gateway at ipcatt.top ---');

  // 1. Check Root Endpoint
  try {
    const rootRes = await fetch(`${API_URL}/`);
    const rootData = await rootRes.json();
    console.log('✅ Root status:', rootData.status);
  } catch (err) {
    console.error('❌ Failed to reach root endpoint:', err.message);
  }

  try {
    const dbListRes = await fetch(`${API_URL}/api/databases`, {
      headers: { 'X-API-Key': API_KEY }
    });
    
    // If response is not ok (e.g. 401, 404, 500)
    if (!dbListRes.ok) {
        const errorText = await dbListRes.text();
        console.error(`❌ Databases API returned error status ${dbListRes.status}:`, errorText.substring(0, 500));
        return;
    }

    const dbListData = await dbListRes.json();
    console.log('✅ Configured databases:', dbListData.configured_databases);

    // 3. Test a sample query on the first database found
    if (dbListData.configured_databases && dbListData.configured_databases.length > 0) {
      const dbName = dbListData.configured_databases[0];
      console.log(`--- Testing query on database: ${dbName} ---`);

      const queryRes = await fetch(`${API_URL}/api/${dbName}/query`, {
        method: 'POST',
        headers: {
          'X-API-Key': API_KEY,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          query: 'SELECT 1 as "connection_test"',
          params: {}
        })
      });

      const queryData = await queryRes.json();
      console.log('✅ Query result:', JSON.stringify(queryData, null, 2));
    }
  } catch (err) {
    console.error('❌ Failed to test databases:', err.message);
  }
}

testGateway();
