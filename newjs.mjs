/**
 * AWS Lambda - Cognito Pre Token Generation Trigger
 *
 * FLOW:
 * Frontend Login → Cognito Auth → Pre Token Lambda Trigger →
 * Aurora MySQL IAM Token → Tenant Schema Query →
 * Roles + Permissions →
 * Inject into JWT
 *
 * PURPOSE:
 * Remove Spring Boot / Middle Tier Role API
 * Direct DB Role Fetch
 */

const mysql = require("mysql2/promise");
const AWS = require("aws-sdk");

/**
 * AWS RDS Signer for Aurora IAM Authentication
 * This generates temporary DB auth token (~15 mins)
 */
const signer = new AWS.RDS.Signer({
    region: process.env.AWS_REGION,
    hostname: process.env.DB_HOST,
    port: Number(process.env.DB_PORT || 3306),
    username: process.env.DB_USER
});

exports.handler = async (event) => {
    console.log("===== PRE TOKEN TRIGGER START =====");
    console.log("Incoming Event:", JSON.stringify(event));

    let connection;

    try {
        /**
         * STEP 1: Extract Cognito User Info
         */
        const cognitoUserId =
            event.request.userAttributes?.sub ||
            event.userName;

        /**
         * Tenant must come from login flow
         * Example:
         * custom:tenantName = client1
         */
        const tenantName =
            event.request.userAttributes["custom:tenantName"];

        /**
         * Validate required fields
         */
        if (!cognitoUserId) {
            console.warn("Missing Cognito User ID");
            return event;
        }

        if (!tenantName) {
            console.warn("Missing tenantName");
            return event;
        }

        /**
         * Security Validation
         * Prevent schema injection
         */
        if (!/^[a-zA-Z0-9_]+$/.test(tenantName)) {
            throw new Error(`Invalid tenant format: ${tenantName}`);
        }

        /**
         * Tenant directly maps to schema
         */
        const schema = tenantName;

        console.log("Cognito User:", cognitoUserId);
        console.log("Tenant Schema:", schema);

        /**
         * STEP 2: Generate Aurora IAM Auth Token
         * Lambda IAM Role must have:
         * rds-db:connect
         */
        const authToken = signer.getAuthToken({
            username: process.env.DB_USER
        });

        console.log("Aurora IAM Token Generated Successfully");

        /**
         * STEP 3: Connect to Aurora MySQL
         */
        connection = await mysql.createConnection({
            host: process.env.DB_HOST,
            user: process.env.DB_USER,
            database: schema,
            password: authToken,
            port: Number(process.env.DB_PORT || 3306),

            /**
             * Required for Aurora IAM Authentication
             */
            ssl: "Amazon RDS",

            authSwitchHandler: ({ pluginName }, cb) => {
                if (pluginName === "mysql_clear_password") {
                    cb(null, authToken + "\0");
                }
            }
        });

        console.log("Aurora Connection Established");

        /**
         * STEP 4: Dynamic Multi-Tenant Role Query
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

        /**
         * STEP 5: Execute Query
         * ? placeholders map in order
         */
        const [rows] = await connection.execute(sql, [
            cognitoUserId,
            cognitoUserId
        ]);

        console.log("DB Rows Returned:", JSON.stringify(rows));

        /**
         * STEP 6: No roles found
         */
        if (!rows.length) {
            console.warn("No roles found for user");

            event.response = {
                claimsOverrideDetails: {
                    claimsToAddOrOverride: {
                        tenantName: tenantName,
                        roles: JSON.stringify([]),
                        permissions: JSON.stringify([])
                    }
                }
            };

            return event;
        }

        /**
         * STEP 7: Extract Unique Roles
         */
        const roles = [
            ...new Set(
                rows
                    .map(row => row.Role_Name)
                    .filter(Boolean)
            )
        ];

        /**
         * STEP 8: Extract Unique Permissions
         */
        const permissions = [
            ...new Set(
                rows
                    .map(row => row.Permission_Name)
                    .filter(Boolean)
            )
        ];

        /**
         * STEP 9: Inject into Cognito JWT
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
                    roles: JSON.stringify(roles),
                    permissions: JSON.stringify(permissions)
                }
            }
        };

        console.log("Roles Injected:", roles);
        console.log("Permissions Injected:", permissions);

    } catch (error) {
        console.error("PRE TOKEN ERROR:", error);

        /**
         * Fail safe:
         * Login should still work even if role fetch fails
         */
        return event;

    } finally {
        /**
         * STEP 10: Always close DB connection
         */
        if (connection) {
            await connection.end();
            console.log("Aurora Connection Closed");
        }

        console.log("===== PRE TOKEN TRIGGER END =====");
    }

    return event;
};
