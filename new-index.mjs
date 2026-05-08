/**
 * AWS Lambda - Cognito Pre Token Generation Trigger (NEW APPROACH)
 *
 * New Flow:
 * Cognito Login → Pre Token Lambda → Direct Aurora MySQL (Tenant Schema) → Roles + Permissions → JWT Claims
 *
 * Removed:
 * ❌ M2M Token Fetch
 * ❌ Spring Boot API Call
 * ❌ Middle Tier Hop
 *
 * Added:
 * ✅ Tenant-based schema resolution
 * ✅ Direct Aurora query
 * ✅ Faster role injection
 */

const mysql = require("mysql2/promise");

/**
 * Tenant → Schema Mapping
 * Ideally move this to DynamoDB / Secrets / Config later
 */
const tenantSchemaMap = {
    client1: "client1",
    client2: "client2",
    client3: "client3"
};

exports.handler = async (event) => {
    console.log("Pre-Token Generation Triggered");
    console.log("Incoming Event:", JSON.stringify(event));

    /**
     * Cognito User ID
     */
    const cognitoUserId =
        event.request.userAttributes?.sub ||
        event.userName;

    /**
     * Tenant Name
     * Frontend must send tenant during login and store it as custom attribute
     * Example:
     * custom:tenantName = client1
     */
    const tenantName =
        event.request.userAttributes["custom:tenantName"];

    if (!tenantName || !tenantSchemaMap[tenantName]) {
        console.warn("Invalid or Missing Tenant Name");
        return event;
    }

    const schema = tenantSchemaMap[tenantName];

    /**
     * DB Config
     * For Aurora Passwordless:
     * Replace password with RDS Signer token generation later if needed
     */
    let connection;

    try {
        connection = await mysql.createConnection({
            host: process.env.DB_HOST,
            user: process.env.DB_USER,
            password: process.env.DB_PASSWORD, // Replace with RDS token if using IAM auth
            ssl: {
                rejectUnauthorized: false
            }
        });

        /**
         * Direct Role + Permission Query
         */
        const sql = `
        SELECT DISTINCT
            CU.Client_User_Id,
            CR.Role_Name,
            UP.Permission_Name
        FROM ${schema}.Client_User CU

        LEFT JOIN ${schema}.Client_User_Client_Role CUCR
            ON CU.Client_User_Id = CUCR.Client_User_Id

        LEFT JOIN ${schema}.Client_Role CR
            ON CUCR.Client_Role_Id = CR.Client_Role_Id

        LEFT JOIN ${schema}.Client_Role_User_Permission CRUP
            ON CR.Client_Role_Id = CRUP.Client_Role_Id

        LEFT JOIN Shared.User_Permission UP
            ON CRUP.User_Permission_Id = UP.User_Permission_Id

        WHERE CU.Cognito_User_Id = ?
          AND CU.Is_Active = 1

        UNION

        SELECT DISTINCT
            CU.Client_User_Id,
            SR.Role_Name,
            UP.Permission_Name
        FROM ${schema}.Client_User CU

        JOIN ${schema}.Client_User_Shared_Role CUSR
            ON CU.Client_User_Id = CUSR.Client_User_Id

        JOIN Shared.Shared_Role SR
            ON CUSR.Shared_Role_Id = SR.Shared_Role_Id

        JOIN Shared.Shared_Role_User_Permission SRUP
            ON SR.Shared_Role_Id = SRUP.Shared_Role_Id

        JOIN Shared.User_Permission UP
            ON SRUP.User_Permission_Id = UP.User_Permission_Id

        WHERE CU.Cognito_User_Id = ?
          AND CU.Is_Active = 1
        `;

        const [rows] = await connection.execute(sql, [
            cognitoUserId,
            cognitoUserId
        ]);

        if (!rows.length) {
            console.warn(`No roles found for user: ${cognitoUserId}`);
            return event;
        }

        /**
         * Extract Roles
         */
        const roles = [
            ...new Set(
                rows.map(r => r.Role_Name).filter(Boolean)
            )
        ];

        /**
         * Extract Permissions
         */
        const permissions = [
            ...new Set(
                rows.map(r => r.Permission_Name).filter(Boolean)
            )
        ];

        /**
         * Inject into JWT
         */
        event.response = {
            claimsOverrideDetails: {
                groupOverrideDetails: {
                    groupsToOverride: roles,
                    iamRolesToOverride: [],
                    preferredRole: null
                },
                claimsToAddOrOverride: {
                    tenantName: tenantName,
                    clientUserId: rows[0].Client_User_Id.toString(),
                    permissions: JSON.stringify(permissions)
                }
            }
        };

        console.log("Roles Injected:", roles);
        console.log("Permissions Injected:", permissions);

    } catch (error) {
        console.error("Pre-Token Error:", error);
    } finally {
        if (connection) {
            await connection.end();
        }
    }

    return event;
};
