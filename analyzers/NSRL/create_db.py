import os
import sqlalchemy as db
from glob import glob

conn_string = "<insert postgres connection string >"
NSRL_folder_path = "/path/to/NSRLFolder/*"

engine = db.create_engine(conn_string)
metadata = db.MetaData()

nsrl = db.Table(
    "nsrl",
    metadata,
    db.Column("id", db.Integer, primary_key=True, autoincrement=True),
    db.Column("sha1", db.String),
    db.Column("md5", db.String),
    db.Column("crc32", db.String),
    db.Column("filename", db.String),
    db.Column("filesize", db.String),
    db.Column("productcode", db.String),
    db.Column("opsystemcode", db.String),
    db.Column("specialcode", db.String),
    db.Column("dbname", db.String),
    db.Column("release", db.String),
    db.Index("idx_sha1", "sha1"),
    db.Index("idx_md5", "md5"),
)
metadata.create_all(engine)

conn = engine.raw_connection()
cursor = conn.cursor()
for NSRL_file_path in glob(NSRL_folder_path):
    dbname, release = NSRL_file_path.split("/")[-1].replace(".txt","").split("_")
    print(dbname, release)
    with open(NSRL_file_path, "r", encoding="latin-1") as f:
        cmd = 'COPY nsrl("sha1", "md5", "crc32", "filename", "filesize", "productcode", "opsystemcode", "specialcode") FROM STDIN WITH (FORMAT CSV, DELIMITER ",", HEADER TRUE)'
        cursor.copy_expert(cmd, f)
        conn.commit()
        engine.execute("update nsrl set dbname='%s', release='%s' where dbname is null" % (dbname, release))
        conn.commit()
cursor.close()
conn.close()
engine.dispose()