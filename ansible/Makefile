.PHONY: raspberrypi

raspberrypi:
	ansible-vault decrypt roles/common/files/id_ed25519 --output /tmp/acme_rpi_id_ed25519
	chmod 600 /tmp/acme_rpi_id_ed25519
