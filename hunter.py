#!/usr/bin/env python3
"""
Oracle Cloud ARM hunter (VM.Standard.A1.Flex) voor GitHub Actions.

- Zoekt dynamisch het nieuwste aarch64-image voor de regio (geen hardcoded image-OCID).
- Controleert eerst of er al een A1-instantie bestaat (voorkomt dubbele aanmaak).
- Probeert meerdere keren per run te lanceren; "Out of host capacity" is normaal en
  geeft exit 0 (geen rode run / geen spam-mails). Echte fouten geven exit 1.
- Schrijft result=created|exists|capacity naar $GITHUB_OUTPUT voor de workflow.

Let op: de logs van een publieke repo zijn publiek. Dit script print daarom
bewust geen OCID's, IP-adressen of sleutels.
"""
import os
import sys
import time
from datetime import datetime, timezone

import oci

SHAPE = "VM.Standard.A1.Flex"
OCPUS = float(os.getenv("OCPUS", "4"))
MEMORY_GB = float(os.getenv("MEMORY_GB", "24"))
BOOT_GB = int(os.getenv("BOOT_VOLUME_GB", "100"))  # minimum 50, free tier totaal 200
DISPLAY_NAME = os.getenv("INSTANCE_NAME", "arm-free")
IMAGE_OS = os.getenv("IMAGE_OS", "Canonical Ubuntu")
IMAGE_OS_VERSION = os.getenv("IMAGE_OS_VERSION", "24.04")
ATTEMPTS = int(os.getenv("ATTEMPTS", "5"))
SLEEP_SECONDS = int(os.getenv("SLEEP_SECONDS", "120"))  # onder ~60s geeft OCI vaak 429
MAX_RUNTIME = int(os.getenv("MAX_RUNTIME_SECONDS", "720"))  # run eindigt altijd netjes < timeout
START = time.monotonic()


def log(msg):
    print(f"[{datetime.now(timezone.utc).strftime('%H:%M:%SZ')}] {msg}", flush=True)


def set_result(value):
    path = os.getenv("GITHUB_OUTPUT")
    if path:
        with open(path, "a") as fh:
            fh.write(f"result={value}\n")


def need(name):
    value = (os.getenv(name) or "").strip().strip("\"'").strip()
    if not value:
        log(f"FOUT: omgevingsvariabele/secret {name} ontbreekt of is leeg.")
        sys.exit(1)
    return value


def fatal(msg):
    log(f"FOUT: {msg}")
    sys.exit(1)


def short(ocid):
    return "..." + ocid[-8:]


def find_existing(compute, compartment_id):
    instances = oci.pagination.list_call_get_all_results(
        compute.list_instances, compartment_id=compartment_id
    ).data
    for inst in instances:
        if inst.shape == SHAPE and inst.lifecycle_state not in ("TERMINATED", "TERMINATING"):
            return inst
    return None


def pick_image(compute, compartment_id):
    images = oci.pagination.list_call_get_all_results(
        compute.list_images,
        compartment_id=compartment_id,
        operating_system=IMAGE_OS,
        operating_system_version=IMAGE_OS_VERSION,
        shape=SHAPE,
        sort_by="TIMECREATED",
        sort_order="DESC",
    ).data
    images = [i for i in images if i.lifecycle_state == "AVAILABLE"]
    if not images:
        fatal(
            f"Geen beschikbaar image gevonden voor '{IMAGE_OS} {IMAGE_OS_VERSION}' "
            f"met shape {SHAPE}. Pas IMAGE_OS / IMAGE_OS_VERSION aan."
        )
    return images[0]


def main():
    compartment_id = need("COMPARTMENT_ID")
    subnet_id = need("SUBNET_ID")
    ssh_key = need("SSH_PUBLIC_KEY")

    # SSH-sleutel moet één regel publieke sleutel zijn (nooit de inhoud loggen)
    if "PRIVATE KEY" in ssh_key or ssh_key.startswith("-----"):
        fatal("SSH_PUBLIC_KEY bevat een PRIVÉsleutel (begint met '-----BEGIN'). "
              "Zet hier de PUBLIEKE sleutel (.pub, één regel die met 'ssh-ed25519' of 'ssh-rsa' begint). "
              "Beschouw de sleutel die in die secret stond als gelekt en vervang hem.")
    if not ssh_key.startswith(("ssh-rsa ", "ssh-ed25519 ", "ecdsa-sha2-", "sk-ssh-ed25519", "sk-ecdsa-")):
        fatal("SSH_PUBLIC_KEY heeft geen geldig formaat; verwacht een regel die met "
              "'ssh-ed25519' of 'ssh-rsa' begint.")
    if "\n" in ssh_key:
        fatal("SSH_PUBLIC_KEY moet één regel zijn (geen regelafbrekingen).")

    # Snelle controle van de OCID's (zonder API-aanroep, zonder iets te loggen)
    sub_parts = subnet_id.split(".")
    if not subnet_id.startswith("ocid1.subnet."):
        kind = sub_parts[1] if len(sub_parts) > 1 else "onbekend"
        fatal(f"SUBNET_ID moet met 'ocid1.subnet.' beginnen, maar is een '{kind}'-OCID "
              "(bijv. een VCN-OCID of een quote/spatie te veel in de secret).")
    if len(sub_parts) > 3 and sub_parts[3] not in ("", "eu-amsterdam-1"):
        fatal(f"SUBNET_ID hoort bij regio '{sub_parts[3]}', niet bij eu-amsterdam-1.")
    if not compartment_id.startswith(("ocid1.compartment.", "ocid1.tenancy.")):
        fatal("COMPARTMENT_ID moet met 'ocid1.compartment.' (of 'ocid1.tenancy.' voor root) beginnen.")

    try:
        config = oci.config.from_file()  # ~/.oci/config, profiel DEFAULT
        oci.config.validate_config(config)
    except Exception as exc:  # noqa: BLE001
        fatal(f"OCI-config ongeldig: {exc}")

    log(f"Regio: {config.get('region')}")

    identity = oci.identity.IdentityClient(config)
    compute = oci.core.ComputeClient(config)
    network = oci.core.VirtualNetworkClient(config)

    # --- Preflight: auth, AD's, subnet, image, bestaande instantie ---------
    hints = {
        "1/4 availability domains (tenancy uit OCI_CONFIG)":
            "Controleer 'tenancy' en 'user' in OCI_CONFIG, de fingerprint en of de API-key bij die user hoort.",
        "2/4 subnet (SUBNET_ID)":
            "SUBNET_ID is onjuist, zit in een andere regio, of de user mag het subnet niet lezen.",
        "3/4 instanties lijsten (COMPARTMENT_ID)":
            "COMPARTMENT_ID is onjuist, of de user heeft geen 'inspect/read instances' rechten in dit compartment.",
        "4/4 image zoeken (COMPARTMENT_ID)":
            "De user heeft geen rechten om images te lezen in dit compartment.",
    }

    def step(label, fn):
        try:
            return fn()
        except oci.exceptions.ServiceError as exc:
            log(f"Stap {label} mislukt: HTTP {exc.status} {exc.code}")
            log(f"Tip: {hints[label]}")
            log(f"opc-request-id: {exc.request_id}")
            sys.exit(1)

    ads = step("1/4 availability domains (tenancy uit OCI_CONFIG)",
               lambda: identity.list_availability_domains(config["tenancy"]).data)
    log("Stap 1/4 OK: authenticatie werkt.")
    subnet = step("2/4 subnet (SUBNET_ID)", lambda: network.get_subnet(subnet_id).data)
    log("Stap 2/4 OK: subnet gevonden.")
    existing = step("3/4 instanties lijsten (COMPARTMENT_ID)",
                    lambda: find_existing(compute, compartment_id))
    log("Stap 3/4 OK: compartment leesbaar.")
    image = None if existing else step("4/4 image zoeken (COMPARTMENT_ID)",
                                       lambda: pick_image(compute, compartment_id))

    if existing:
        log(f"Er bestaat al een {SHAPE}-instantie (status {existing.lifecycle_state}). Niets te doen.")
        set_result("exists")
        return

    assign_public_ip = not subnet.prohibit_public_ip_on_vnic
    log(f"Image: {image.display_name}")
    log(f"ADs: {len(ads)} | publiek IP: {assign_public_ip} | {OCPUS:g} OCPU / {MEMORY_GB:g} GB / {BOOT_GB} GB boot")

    for attempt in range(1, ATTEMPTS + 1):
        if time.monotonic() - START > MAX_RUNTIME:
            log("Maximale looptijd van deze run bereikt; stop netjes.")
            break
        pause = SLEEP_SECONDS
        for ad in ads:
            details = oci.core.models.LaunchInstanceDetails(
                availability_domain=ad.name,
                compartment_id=compartment_id,
                display_name=DISPLAY_NAME,
                shape=SHAPE,
                shape_config=oci.core.models.LaunchInstanceShapeConfigDetails(
                    ocpus=OCPUS, memory_in_gbs=MEMORY_GB
                ),
                source_details=oci.core.models.InstanceSourceViaImageDetails(
                    image_id=image.id, boot_volume_size_in_gbs=BOOT_GB
                ),
                create_vnic_details=oci.core.models.CreateVnicDetails(
                    subnet_id=subnet_id, assign_public_ip=assign_public_ip
                ),
                metadata={"ssh_authorized_keys": ssh_key},
            )
            try:
                resp = compute.launch_instance(details)
            except oci.exceptions.ServiceError as exc:
                text = f"{exc.code} {exc.message}".lower()
                if exc.status == 429:
                    log(f"Poging {attempt}/{ATTEMPTS}: rate limit (429), volgende poging wacht langer.")
                    pause = SLEEP_SECONDS * 2
                elif exc.status >= 500 or "capacity" in text:
                    log(f"Poging {attempt}/{ATTEMPTS}: geen capaciteit (HTTP {exc.status}).")
                else:
                    # 400 LimitExceeded, 404 NotAuthorizedOrNotFound, 401, ... = echte fout
                    fatal(f"HTTP {exc.status} {exc.code}: {exc.message}")
                continue

            inst = resp.data
            log(f"GELUKT: instantie aangemaakt ({short(inst.id)}), wacht op RUNNING...")
            try:
                oci.wait_until(
                    compute,
                    compute.get_instance(inst.id),
                    "lifecycle_state",
                    "RUNNING",
                    max_wait_seconds=600,
                )
                log("Instantie is RUNNING. Zie de OCI-console voor het publieke IP.")
            except Exception as exc:  # noqa: BLE001
                log(f"Kon RUNNING-status niet bevestigen ({exc}); controleer de console.")
            set_result("created")
            return

        if attempt < ATTEMPTS:
            remaining = MAX_RUNTIME - (time.monotonic() - START)
            time.sleep(max(0, min(pause, remaining)))

    log("Geen capaciteit gevonden in deze run. Volgende cron-run probeert opnieuw.")
    set_result("capacity")


if __name__ == "__main__":
    main()