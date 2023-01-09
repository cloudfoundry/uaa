CREATE TABLE orchestrator_zone (
    id serial NOT NULL constraint orchestrator_zone_pk PRIMARY KEY,
    identity_zone_id VARCHAR(36)  NOT NULL,
    orchestrator_zone_name  VARCHAR(255)  NOT NULL,
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    lastmodified TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE UNIQUE INDEX identity_zone_id_unique_key ON orchestrator_zone (identity_zone_id);

CREATE UNIQUE INDEX orchestrator_name_unique_key ON orchestrator_zone (orchestrator_zone_name);

ALTER TABLE orchestrator_zone ADD CONSTRAINT fk_orchestrator_identity_zone FOREIGN KEY (identity_zone_id)
    REFERENCES identity_zone (id);