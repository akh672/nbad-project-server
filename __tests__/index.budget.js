const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../index');

// Use a separate test database to avoid interference with the actual database
const testDbUri = 'mongodb://127.0.0.1:27017/test_database'; // Update with your test database URI

beforeAll(async () => {
  // Connect to the test database
  await mongoose.connect(testDbUri, { useNewUrlParser: true, useUnifiedTopology: true });
});

afterAll(async () => {
  // Disconnect and close the database connection
  await mongoose.connection.close();
});

describe('Index.js API Tests', () => {
  let server; // Added a variable to store the server instance

  beforeAll((done) => {
    // Start the server and store the instance in the 'server' variable
    server = app.listen(3000, () => {
      console.log(`Server running on port ${PORT}`);
      done(); // Call 'done' to signal that the server has started
    });
  });

  afterAll((done) => {
    // Close the server and call 'done' when it's fully closed
    server.close(() => {
      console.log('Server closed');
      done();
    });
  });

  let authToken;

  // ... (rest of your test cases)

  // Uncomment the following block if you need to authenticate before tests
  // beforeAll(async () => {
  //   // Authenticate and obtain the token before running tests
  //   const response = await request(app)
  //     .post('/api/v1/auth/login')
  //     .send({
  //       // Provide valid login credentials here
  //       email: 'your@email.com',
  //       password: 'your_password',
  //     });
  //   authToken = response.body.token;
  // });

  // ... (rest of your test cases)

});
