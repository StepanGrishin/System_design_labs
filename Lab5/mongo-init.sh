set -e

mongo <<EOF
db = db.getSiblingDB('arch')
db.messages.createIndex({"id_user": -1}) 
EOF
