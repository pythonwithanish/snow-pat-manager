CREATE OR REPLACE PROCEDURE SUPPORT_DB.SECURITY.SP_PAT_STATUS("P_CALLER" VARCHAR, "P_SERVICE_USER" VARCHAR)
RETURNS VARCHAR
LANGUAGE JAVASCRIPT
EXECUTE AS OWNER
AS '
  var caller = P_CALLER;
  if (!caller || caller.trim() === '''') {
    return JSON.stringify({STATUS: "FAILED", ERROR: "INVALID REQUEST: Caller identity is required."});
  }
  caller = caller.trim().toUpperCase();

  var authStmt = snowflake.createStatement({
    sqlText: "SELECT COUNT(*) FROM SUPPORT_DB.SECURITY.SVC_ACC_OWNER_MAPPING WHERE UPPER(OWNER_USER) = ? AND UPPER(SERVICE_USER) = UPPER(?) AND ACTIVE = ''Y''",
    binds: [caller, P_SERVICE_USER]
  });
  var authResult = authStmt.execute();
  authResult.next();
  if (authResult.getColumnValue(1) === 0) {
    return JSON.stringify({STATUS: "FAILED", ERROR: "ACCESS DENIED: You are not authorized to view PAT status for this service account."});
  }

  try {
    var showStmt = snowflake.createStatement({
      sqlText: "SHOW USER PROGRAMMATIC ACCESS TOKENS FOR USER IDENTIFIER(?)",
      binds: [P_SERVICE_USER]
    });
    showStmt.execute();
    
    var scanStmt = snowflake.createStatement({
      sqlText: "SELECT TO_CHAR(\\"name\\") AS token_name, TO_CHAR(\\"expires_at\\") AS expires_at, TO_CHAR(\\"status\\") AS status, TO_CHAR(\\"created_on\\") AS created_on, DATEDIFF(''day'', CURRENT_TIMESTAMP(), TO_TIMESTAMP_LTZ(TO_CHAR(\\"expires_at\\"))) AS remaining FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()))"
    });
    var scanResult = scanStmt.execute();
    
    var tokens = [];
    while (scanResult.next()) {
      tokens.push({
        SERVICE_USER: P_SERVICE_USER,
        TOKEN_NAME: scanResult.getColumnValue(1),
        TOKEN_EXPIRES_ON: scanResult.getColumnValue(2),
        STATUS: scanResult.getColumnValue(3),
        TOKEN_CREATED_ON: scanResult.getColumnValue(4),
        REMAINING_VALIDITY_DAYS: scanResult.getColumnValue(5)
      });
    }
    
    return JSON.stringify({STATUS: "SUCCESS", TOKENS: tokens});
  } catch (err) {
    return JSON.stringify({STATUS: "FAILED", ERROR: err.message});
  }
';
