import streamlit as st
import json
import pandas as pd
from snowflake.snowpark.context import get_active_session

st.set_page_config(page_title="PAT Management Portal", layout="wide")

session = get_active_session()
current_user = st.user.user_name

st.title("PAT Management Portal")
st.caption(f"Logged in as **{current_user}**")

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
    st.info("No active service accounts are mapped to your user.")
    st.stop()

selected_svc = st.selectbox("Service Account", service_accounts)

st.divider()

# --- Status ---
if st.button("Show PAT Status"):
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
                df.columns = ["Name", "Status", "Created", "Expires", "Days Left"]
                st.dataframe(df, use_container_width=True)
            else:
                st.info("No PATs found.")
        else:
            st.error(result_data.get("ERROR"))
    except Exception as e:
        st.error(str(e))

st.divider()

# --- Create ---
st.subheader("Create PAT")
token_name = st.text_input("Token Name", key="create_name")

if st.button("Create"):
    if not token_name.strip():
        st.error("Token name is required.")
    else:
        try:
            result = session.sql(
                f"CALL SUPPORT_DB.SECURITY.SP_PAT_CREATE('{current_user}', '{selected_svc}', '{token_name.strip().upper()}')"
            ).collect()
            data = json.loads(result[0][0])
            if data.get("STATUS") == "SUCCESS":
                st.success("PAT created.")
                st.warning("Copy this token now. It will not be shown again.")
                st.code(data.get("PAT_SECRET", ""))
            else:
                st.error(data.get("ERROR"))
        except Exception as e:
            st.error(str(e))

st.divider()

# --- Rotate ---
st.subheader("Rotate PAT")
rotate_name = st.text_input("Token Name to Rotate", key="rotate_name")

if st.button("Rotate"):
    if not rotate_name.strip():
        st.error("Token name is required.")
    else:
        try:
            result = session.sql(
                f"CALL SUPPORT_DB.SECURITY.SP_PAT_ROTATE('{current_user}', '{selected_svc}', '{rotate_name.strip().upper()}')"
            ).collect()
            data = json.loads(result[0][0])
            if data.get("STATUS") == "SUCCESS":
                st.success("PAT rotated. Old token expired immediately.")
                st.warning("Copy this token now. It will not be shown again.")
                st.code(data.get("PAT_SECRET", ""))
            else:
                st.error(data.get("ERROR"))
        except Exception as e:
            st.error(str(e))
