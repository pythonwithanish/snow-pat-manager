import streamlit as st
import json
import pandas as pd
from snowflake.snowpark.context import get_active_session

st.set_page_config(page_title="Snowflake PAT Management Portal", layout="wide")

session = get_active_session()

current_user = session.sql("SELECT CURRENT_USER()").collect()[0][0]

st.title("Snowflake PAT Management Portal")
st.markdown("---")
st.markdown(f"**Logged-in User:** `{current_user}`")

# Get authorized service accounts
mappings_df = session.sql(f"""
    SELECT SERVICE_USER 
    FROM SUPPORT_DB.SECURITY.SVC_ACC_OWNER_MAPPING 
    WHERE UPPER(OWNER_USER) = UPPER('{current_user}') 
    AND ACTIVE = 'Y'
    ORDER BY SERVICE_USER
""").collect()

service_accounts = [row[0] for row in mappings_df]

if not service_accounts:
    st.warning("No active service accounts are mapped to your Snowflake user.")
    st.stop()

st.markdown(f"**Your Service Accounts:** {len(service_accounts)}")
selected_svc = st.selectbox("Select Service Account", service_accounts)

st.markdown("---")

# --- PAT Status Section ---
st.subheader("PAT Status")

if st.button("Refresh Status", key="refresh_status"):
    st.experimental_rerun()

try:
    status_result = session.sql(
        f"CALL SUPPORT_DB.SECURITY.SP_PAT_STATUS('{current_user}', '{selected_svc}')"
    ).collect()
    result_data = json.loads(status_result[0][0])
    
    if result_data.get("STATUS") == "SUCCESS":
        tokens = result_data.get("TOKENS", [])
        if tokens:
            df = pd.DataFrame(tokens)
            df = df[["TOKEN_NAME", "STATUS", "TOKEN_CREATED_ON", "TOKEN_EXPIRES_ON", "REMAINING_VALIDITY_DAYS"]]
            df.columns = ["Token Name", "Status", "Created", "Expires", "Remaining Days"]
            st.dataframe(df, use_container_width=True)
        else:
            st.info("No PATs found for this service account.")
    else:
        st.error(result_data.get("ERROR", "Unable to retrieve PAT status."))
except Exception as e:
    st.error(f"Unable to retrieve PAT status: {str(e)}")

st.markdown("---")

# --- Create PAT Section ---
st.subheader("Create PAT")

with st.form("create_pat_form"):
    token_name = st.text_input("Token Name", placeholder="e.g., MY_SERVICE_TOKEN")
    create_submitted = st.form_submit_button("Create PAT")
    
    if create_submitted:
        if not token_name.strip():
            st.error("Token name is required.")
        else:
            try:
                create_result = session.sql(
                    f"CALL SUPPORT_DB.SECURITY.SP_PAT_CREATE('{current_user}', '{selected_svc}', '{token_name.strip().upper()}')"
                ).collect()
                result_data = json.loads(create_result[0][0])
                
                if result_data.get("STATUS") == "SUCCESS":
                    st.success("PAT created successfully!")
                    st.warning(
                        "**IMPORTANT:** This PAT will be displayed only once. "
                        "Store it securely. It cannot be retrieved later."
                    )
                    st.code(result_data.get("PAT_SECRET", ""), language=None)
                    st.markdown(f"**Token Name:** `{result_data.get('TOKEN_NAME')}`")
                    st.markdown(f"**Created:** `{result_data.get('TOKEN_CREATED_ON')}`")
                    st.markdown(f"**Expires:** `{result_data.get('TOKEN_EXPIRES_ON')}`")
                else:
                    st.error(result_data.get("ERROR", "PAT creation failed."))
            except Exception as e:
                st.error(f"PAT creation failed: {str(e)}")

st.markdown("---")

# --- Rotate PAT Section ---
st.subheader("Rotate PAT")

with st.form("rotate_pat_form"):
    rotate_token_name = st.text_input("Token Name to Rotate", placeholder="e.g., MY_SERVICE_TOKEN")
    rotate_submitted = st.form_submit_button("Rotate PAT")
    
    if rotate_submitted:
        if not rotate_token_name.strip():
            st.error("Token name is required.")
        else:
            try:
                rotate_result = session.sql(
                    f"CALL SUPPORT_DB.SECURITY.SP_PAT_ROTATE('{current_user}', '{selected_svc}', '{rotate_token_name.strip().upper()}')"
                ).collect()
                result_data = json.loads(rotate_result[0][0])
                
                if result_data.get("STATUS") == "SUCCESS":
                    st.success("PAT rotated successfully!")
                    st.warning(
                        "**IMPORTANT:** This PAT will be displayed only once. "
                        "Store it securely. It cannot be retrieved later."
                    )
                    st.code(result_data.get("PAT_SECRET", ""), language=None)
                    st.markdown(f"**New Token Name:** `{result_data.get('TOKEN_NAME')}`")
                    st.markdown(f"**Created:** `{result_data.get('TOKEN_CREATED_ON')}`")
                    st.markdown(f"**Expires:** `{result_data.get('TOKEN_EXPIRES_ON')}`")
                else:
                    st.error(result_data.get("ERROR", "PAT rotation failed."))
            except Exception as e:
                st.error(f"PAT rotation failed: {str(e)}")
