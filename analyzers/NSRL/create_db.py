import sqlalchemy as db

conn_string = "<insert connection string here>"
NSRL_file_path = "NSRLFile.txt"

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
    db.Index("idx_sha1", "sha1"),
    db.Index("idx_md5", "md5"),
)
metadata.create_all(engine)

with open(NSRL_file_path, "r", encoding="latin-1") as f:
    conn = engine.raw_connection()
    cursor = conn.cursor()
    cmd = 'COPY nsrl("sha1", "md5", "crc32", "filename", "filesize", "productcode", "opsystemcode", "specialcode") FROM STDIN WITH (FORMAT CSV, DELIMITER ",", HEADER TRUE)'
    cursor.copy_expert(cmd, f)
    conn.commit()
    conn.close()

engine.dispose()
