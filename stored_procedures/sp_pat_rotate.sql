CREATE OR REPLACE PROCEDURE SUPPORT_DB.SECURITY.SP_PAT_ROTATE("P_CALLER" VARCHAR, "P_SERVICE_USER" VARCHAR, "P_TOKEN_NAME" VARCHAR)
RETURNS VARCHAR
LANGUAGE JAVASCRIPT
EXECUTE AS OWNER
AS '
  var caller = P_CALLER;
  if (!caller || caller.trim() === '''') {
    return JSON.stringify({STATUS: "FAILED", ERROR: "INVALID REQUEST: Caller identity is required."});
  }
  caller = caller.trim().toUpperCase();
  
  var tokenName = P_TOKEN_NAME.trim().toUpperCase();
  if (!/^[A-Z_][A-Z0-9_]*$/.test(tokenName)) {
    return JSON.stringify({STATUS: "FAILED", ERROR: "INVALID TOKEN NAME: Must contain only letters, numbers, underscores and start with a letter or underscore."});
  }
  
  var reqIdStmt = snowflake.createStatement({sqlText: "SELECT UUID_STRING()"});
  var reqIdResult = reqIdStmt.execute();
  reqIdResult.next();
  var requestId = String(reqIdResult.getColumnValue(1));

  var authStmt = snowflake.createStatement({
    sqlText: "SELECT COUNT(*) FROM SUPPORT_DB.SECURITY.SVC_ACC_OWNER_MAPPING WHERE UPPER(OWNER_USER) = ? AND UPPER(SERVICE_USER) = UPPER(?) AND ACTIVE = ''Y''",
    binds: [caller, P_SERVICE_USER]
  });
  var authResult = authStmt.execute();
  authResult.next();
  if (authResult.getColumnValue(1) === 0) {
    snowflake.createStatement({
      sqlText: "INSERT INTO SUPPORT_DB.SECURITY.PAT_ACTIVITY_LOG (OWNER_USER, SERVICE_USER, ACTION, TOKEN_NAME, RESULT, ERROR_MESSAGE, REQUEST_ID) VALUES (?, ?, ''ROTATE'', ?, ''FAILED'', ''ACCESS DENIED'', ?)",
      binds: [caller, P_SERVICE_USER, tokenName, requestId]
    }).execute();
    return JSON.stringify({STATUS: "FAILED", ERROR: "ACCESS DENIED: You are not authorized to manage this service account."});
  }

  try {
    var svcUser = P_SERVICE_USER.trim().toUpperCase();
    var rotateSql = "ALTER USER " + svcUser + " ROTATE PROGRAMMATIC ACCESS TOKEN " + tokenName + " EXPIRE_ROTATED_TOKEN_AFTER_HOURS = 0";
    var rotateStmt = snowflake.createStatement({sqlText: rotateSql});
    var rotateResult = rotateStmt.execute();
    rotateResult.next();
    var newTokenName = String(rotateResult.getColumnValue(1) || '''');
    var newTokenSecret = String(rotateResult.getColumnValue(2) || '''');

    // Get metadata
    snowflake.createStatement({
      sqlText: "SHOW USER PROGRAMMATIC ACCESS TOKENS FOR USER IDENTIFIER(?)",
      binds: [P_SERVICE_USER]
    }).execute();
    
    var scanStmt = snowflake.createStatement({
      sqlText: "SELECT \\"created_on\\"::VARCHAR, \\"expires_at\\"::VARCHAR FROM TABLE(RESULT_SCAN(LAST_QUERY_ID())) WHERE \\"name\\" = ?",
      binds: [newTokenName]
    });
    var scanResult = scanStmt.execute();
    var tokenCreatedOn = '''';
    var tokenExpiresOn = '''';
    if (scanResult.next()) {
      tokenCreatedOn = String(scanResult.getColumnValue(1) || '''');
      tokenExpiresOn = String(scanResult.getColumnValue(2) || '''');
    }

    snowflake.createStatement({
      sqlText: "INSERT INTO SUPPORT_DB.SECURITY.PAT_ACTIVITY_LOG (OWNER_USER, SERVICE_USER, ACTION, TOKEN_NAME, TOKEN_CREATED_ON, TOKEN_EXPIRES_ON, RESULT, REQUEST_ID) VALUES (?, ?, ''ROTATE'', ?, TRY_TO_TIMESTAMP_LTZ(?), TRY_TO_TIMESTAMP_LTZ(?), ''SUCCESS'', ?)",
      binds: [caller, P_SERVICE_USER, newTokenName, tokenCreatedOn, tokenExpiresOn, requestId]
    }).execute();

    return JSON.stringify({
      STATUS: "SUCCESS",
      SERVICE_USER: P_SERVICE_USER,
      TOKEN_NAME: newTokenName,
      TOKEN_CREATED_ON: tokenCreatedOn,
      TOKEN_EXPIRES_ON: tokenExpiresOn,
      PAT_SECRET: newTokenSecret
    });
  } catch (err) {
    snowflake.createStatement({
      sqlText: "INSERT INTO SUPPORT_DB.SECURITY.PAT_ACTIVITY_LOG (OWNER_USER, SERVICE_USER, ACTION, TOKEN_NAME, RESULT, ERROR_MESSAGE, REQUEST_ID) VALUES (?, ?, ''ROTATE'', ?, ''FAILED'', ?, ?)",
      binds: [caller, P_SERVICE_USER, tokenName, err.message, requestId]
    }).execute();
    return JSON.stringify({STATUS: "FAILED", ERROR: err.message});
  }
';
