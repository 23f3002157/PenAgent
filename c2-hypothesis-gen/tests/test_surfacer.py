from hgs.surfacer import CandidateSurfacer


def test_candidate_surfacer(sample_attack_surface):
    surfacer = CandidateSurfacer()
    candidates = surfacer.surface_candidates(sample_attack_surface)

    # API1: BOLA should have users and vault
    bola_ids = [n["id"] for n in candidates["API1:BOLA"]]
    assert "op_users_get_profile" in bola_ids
    assert "op_vault_get_document" in bola_ids

    # API2: Broken Auth should have auth exchange token
    auth_ids = [n["id"] for n in candidates["API2:Broken_Auth"]]
    assert "op_auth_post_exchange_token" in auth_ids

    # API5: BFLA should have admin purge cache
    bfla_ids = [n["id"] for n in candidates["API5:BFLA"]]
    assert "op_admin_delete_purge_cache" in bfla_ids

    # API8: Misconfiguration should have debug env
    misconfig_ids = [n["id"] for n in candidates["API8:Security_Misconfiguration"]]
    assert "op_debug_get_env" in misconfig_ids
