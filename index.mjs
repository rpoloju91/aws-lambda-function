/**
 * AWS Lambda - Cognito Pre Token Generation Trigger
 * 
 * This function intercepts a Cognito login, uses OAuth2 M2M flow to authenticate
 * itself to the internal Spring Boot Role API, fetches the user's specific roles,
 * and injects them into the user's JWT token.
 */
export const handler = async (event) => {
    console.log("Pre-Token Generation Event triggered for user:", event.userName);

    // Get the user's Cognito ID and Pool ID
    // event.userName usually contains the sub (cognitoUserId) but we can fallback to event.request.userAttributes.sub
    const cognitoUserId = event.userName;
    const userPoolId = event.userPoolId;
    
    // Environment Variables (Set these in Terraform / CloudFormation / AWS Console)
    const apiUrl = process.env.ROLE_API_URL; 
    const clientId = process.env.CLIENT_ID;
    const clientSecret = process.env.CLIENT_SECRET;
    const tokenUrl = process.env.TOKEN_URL;

    if (!apiUrl || !clientId || !clientSecret || !tokenUrl) {
        console.warn("One or more Environment Variables are missing. Returning token without modifications.");
        return event;
    }

    try {
        // --- STEP 1: Get Access Token from Cognito (M2M Flow) ---
        console.log("Fetching M2M Access Token from Cognito...");
        const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
        
        const tokenResponse = await fetch(tokenUrl, {
            method: 'POST',
            headers: {
                'Authorization': `Basic ${basicAuth}`,
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: 'grant_type=client_credentials'
        });

        if (!tokenResponse.ok) {
            console.error(`Failed to get M2M token. Status: ${tokenResponse.status}`);
            return event; 
        }

        const tokenData = await tokenResponse.json();
        const accessToken = tokenData.access_token;

        // --- STEP 2: Call the Spring Boot API to fetch roles ---
        console.log(`Calling Spring Boot Role API for User: ${cognitoUserId}, Pool: ${userPoolId}`);
        const response = await fetch(`${apiUrl}?userId=${encodeURIComponent(cognitoUserId)}&poolId=${encodeURIComponent(userPoolId)}`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json'
            }
        });

        if (!response.ok) {
            console.error(`Role API failed with status: ${response.status}`);
            return event; 
        }

        // --- STEP 3: Parse and Inject the roles ---
        const data = await response.json();
        const roles = data.roles || [];

        event.response = {
            claimsOverrideDetails: {
                groupOverrideDetails: {
                    groupsToOverride: roles,
                    iamRolesToOverride: [],
                    preferredRole: null
                }
            }
        };

        console.log(`Successfully injected roles: ${roles.join(', ')}`);

    } catch (error) {
        console.error("Error during Pre-Token Generation execution:", error);
    }

    return event;
};
