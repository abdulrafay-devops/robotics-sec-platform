import urllib.request
import os

schema_dir = os.path.dirname(os.path.abspath(__file__))
schema_file_path = os.path.join(schema_dir, "02-guacamole-schema.sql")

url_schema = "https://raw.githubusercontent.com/apache/guacamole-client/1.5.5/extensions/guacamole-auth-jdbc/modules/guacamole-auth-jdbc-postgresql/schema/001-create-schema.sql"
url_admin = "https://raw.githubusercontent.com/apache/guacamole-client/1.5.5/extensions/guacamole-auth-jdbc/modules/guacamole-auth-jdbc-postgresql/schema/002-create-admin-user.sql"

try:
    print("Fetching Guacamole PostgreSQL schema...")
    with urllib.request.urlopen(url_schema) as response:
        schema_sql = response.read().decode('utf-8')
        
    print("Fetching Guacamole PostgreSQL default admin user...")
    with urllib.request.urlopen(url_admin) as response:
        admin_sql = response.read().decode('utf-8')
        
    merged_sql = schema_sql + "\n\n" + admin_sql
    
    with open(schema_file_path, "w", encoding="utf-8") as f:
        f.write(merged_sql)
        
    print(f"Successfully assembled schema and saved to: {schema_file_path}")
    
except Exception as e:
    print(f"Error fetching schema: {e}")
