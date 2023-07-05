

CREATE TABLE zones (
    id UUID PRIMARY KEY,
    domain TEXT NOT NULL,
    authoritative BOOLEAN NOT NULL,
    allow_md5_tsig BOOLEAN NOT NULL
);

CREATE UNIQUE INDEX zone_name ON zones(domain);

CREATE TABLE zone_soas (
    id UUID PRIMARY KEY REFERENCES zones(id) ON DELETE CASCADE,
    mname TEXT NOT NULL,
    rname TEXT NOT NULL,
    soa_serial INT4 NOT NULL,
    refresh INT4 NOT NULL,
    retry INT4 NOT NULL,
    expire INT4 NOT NULL,
    minimum INT4 NOT NULL
);

CREATE TABLE zone_nameservers (
    id UUID PRIMARY KEY,
    zone_id UUID NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
    name TEXT NOT NULL
);

CREATE INDEX zone_nameservers_idx ON zone_nameservers(zone_id);

CREATE TABLE zone_tsig_keys (
    id UUID PRIMARY KEY,
    zone_id UUID NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    keydata TEXT NOT NULL
);

CREATE INDEX zone_tsig_keys_idx ON zone_tsig_keys(zone_id);

CREATE TABLE zone_records (
    zone_id UUID NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
    ordering INT4 NOT NULL,
    name TEXT NOT NULL,
    dns_type TEXT NOT NULL,
    ttl INT4 NOT NULL,
    data TEXT NOT NULL,
    PRIMARY KEY (zone_id, ordering)
);
