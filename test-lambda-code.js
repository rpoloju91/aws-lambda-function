// test-local.mjs
import { handler } from './index.mjs';

// 1. Mock the Environment Variables
process.env.ROLE_API_URL = 'http://localhost:8080'; 
process.env.INTERNAL_API_KEY = 'dev-secret-key-12345';

// 2. Mock the Cognito Event (Simplified V2 Event)
const mockEvent = {
    version: "2",
    triggerSource: "TokenGeneration_Authentication",
    request: {
        userAttributes: {
            sub: "user-123-abc-789" // The ID your Spring Boot API expects
        }
    },
    response: {
        claimsAndScopeOverrideDetails: {
            accessTokenGeneration: {},
            idTokenGeneration: {}
        }
    }
};

// 3. Run the handler
console.log("--- Starting Local Lambda Test ---");
handler(mockEvent)
    .then(result => {
        console.log("Resulting Event:", JSON.stringify(result, null, 2));
    })
    .catch(err => {
        console.error("Test Failed:", err);
    });