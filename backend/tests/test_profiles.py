import pytest

from app.models.user import Role
from app.security.firewall import CommandBlocked, CommandSafetyFirewall, ExecutionContext
from app.security.policy import COMMAND_ALLOWLIST, COMMAND_POLICIES, Operation
from app.services.alcatel.profiles import (
    AOS6_PROFILE,
    AOS7_PROFILE,
    AOS8_PROFILE,
    BUILTIN_PROFILES,
    BounceMethod,
    CommandProfile,
    PortBounceStrategy,
    ProfileLintError,
    Verification,
    is_poe_model,
    lint_read_command,
    lint_write_template,
    model_family,
    version_matches_prefix,
)
from app.services.alcatel.registry import select_profile

CTX = ExecutionContext(1, "admin", Role.ADMIN, "TEST")
FW = CommandSafetyFirewall()


def render(profile, key, **params) -> str:
    op = next(op for op, pol in COMMAND_POLICIES.items() if key in pol.commands)
    return FW.build(CTX, session_id="s", device="SW", operation=op, command_key=key,
                    params=params, profile=profile).text


def test_builtin_profiles_pass_linter_and_are_read_only():
    for profile in BUILTIN_PROFILES.values():
        profile.validate()
        assert all(c.read_only for c in profile.commands.values())
        assert all(c.template in COMMAND_ALLOWLIST[k] for k, c in profile.commands.items())


def test_every_command_has_a_documentation_source():
    for profile in (AOS6_PROFILE, AOS8_PROFILE):
        for cmd in profile.commands.values():
            assert cmd.source and cmd.verification is not Verification.UNVERIFIED
        for strat in profile.strategies:
            assert strat.source


@pytest.mark.parametrize("bad", [
    "interfaces port {port} admin-state disable",
    "show system | more",
    "show system; reload",
    "show mac-learning flush",
    "no show system",
    "show {password}",
    "show  system",
    "show vlan members port {port} && reload",
    "write memory",
    "SHOW SYSTEM",
    "show system",               # harmless, but not allowlisted for mac_lookup
    "show configuration snapshot",
])
def test_read_linter_accepts_only_allowlisted_templates(bad):
    with pytest.raises(ProfileLintError):
        lint_read_command("mac_lookup", bad)
    lint_read_command("mac_lookup", "show mac-learning mac-address {mac}")


def test_write_grammar_is_strict():
    lint_write_template(PortBounceStrategy.INTERFACE_ADMIN, "interfaces {port} admin down",
                        "interfaces {port} admin up")
    with pytest.raises(ProfileLintError):
        lint_write_template(PortBounceStrategy.INTERFACE_ADMIN, "interfaces {port} admin down",
                            "reload all")
    with pytest.raises(ProfileLintError):
        lint_write_template(PortBounceStrategy.INTERFACE_ADMIN_STATE,
                            "interfaces port {port} admin-state disable; write memory",
                            "interfaces port {port} admin-state enable")
    with pytest.raises(ProfileLintError):  # cross-strategy templates are rejected
        lint_write_template(PortBounceStrategy.LANPOWER_STOP_START,
                            "interfaces {port} admin down", "interfaces {port} admin up")


def test_profile_rejects_write_command_disguised_as_read():
    data = AOS8_PROFILE.to_dict()
    data["key"], data["builtin"] = "EVIL", False
    data["commands"]["mac_lookup"]["template"] = "interfaces port {port} admin-state disable"
    with pytest.raises(ProfileLintError):
        CommandProfile.from_dict(data)


def test_render_uses_verified_aos_syntax():
    assert render(AOS8_PROFILE, "mac_lookup", mac="0011.2233.4455") == \
        "show mac-learning mac-address 00:11:22:33:44:55"
    assert render(AOS6_PROFILE, "mac_lookup", mac="001122334455") == \
        "show mac-address-table 00:11:22:33:44:55"
    assert render(AOS8_PROFILE, "vlan_port", port="1/1/26") == "show vlan members port 1/1/26"
    assert render(AOS6_PROFILE, "vlan_port", port="1/26") == "show vlan port 1/26"
    assert render(AOS8_PROFILE, "lldp_port", port="1/1/26") == \
        "show lldp port 1/1/26 remote-system"
    assert render(AOS6_PROFILE, "lldp_port", port="1/26") == "show lldp 1/26 remote-system"


def test_render_rejects_wrong_port_format_per_family():
    with pytest.raises(CommandBlocked):
        render(AOS6_PROFILE, "vlan_port", port="1/1/26")  # OS6450 uses slot/port
    with pytest.raises(CommandBlocked):
        render(AOS8_PROFILE, "vlan_port", port="1/26")
    with pytest.raises(CommandBlocked):
        render(AOS8_PROFILE, "vlan_port", port="1/1/26; reload")


async def test_bounce_commands_per_aos_generation():
    cases = [
        (AOS6_PROFILE, BounceMethod.LINK_BOUNCE, "1/26",
         ["interfaces 1/26 admin down", "interfaces 1/26 admin up"]),
        (AOS8_PROFILE, BounceMethod.LINK_BOUNCE, "1/1/26",
         ["interfaces port 1/1/26 admin-state disable", "interfaces port 1/1/26 admin-state enable"]),
        (AOS6_PROFILE, BounceMethod.POE_CYCLE, "1/26",
         ["lanpower stop 1/26", "lanpower start 1/26"]),
        (AOS8_PROFILE, BounceMethod.POE_CYCLE, "1/1/26",
         ["lanpower port 1/1/26 admin-state disable", "lanpower port 1/1/26 admin-state enable"]),
    ]
    for profile, method, port, expected in cases:
        strategy = profile.strategies_for(method)[0]
        report = await FW.safety_test(CTX, device="SW", port=port, profile=profile,
                                      strategy_spec=strategy, execution_reason="test")
        assert [c["text"] for c in report.commands] == expected
        assert report.safety == "PASS"
        # The spec's example "interfaces 1/1/26 admin down" is never produced.
        assert "interfaces 1/1/26 admin down" not in expected


def test_version_prefix_matching_is_dotted():
    assert version_matches_prefix("8.10.94.R03", "8.10")
    assert not version_matches_prefix("8.1.1.R01", "8.10")
    assert version_matches_prefix("8.1.1.R01", "8.1")
    assert not version_matches_prefix("8.10.94.R03", "8.1")
    assert version_matches_prefix("6.7.2.191.R08", "6")


class _Sw:
    def __init__(self, version="", profile_key="", model=""):
        self.aos_version, self.profile_key, self.model = version, profile_key, model


def test_profile_selection():
    sel = lambda v, m: select_profile(BUILTIN_PROFILES, _Sw(v, model=m))  # noqa: E731
    assert sel("8.10.94.R03", "OS6860E-P24")[0] is AOS8_PROFILE
    assert sel("8.9.221.R03", "OS6360-P10")[0] is AOS8_PROFILE
    assert sel("8.9.221.R03", "OS6465-P12")[0] is AOS8_PROFILE
    assert sel("6.7.2.191.R08", "OS6450-P24")[0] is AOS6_PROFILE
    assert sel("6.7.2.191.R08", "OS6350-24")[0] is AOS6_PROFILE
    profile, reason = sel("7.3.4.380.R02", "OS10K")
    assert profile is None and "not verified" in reason
    assert sel("", "OS6860E-P24")[0] is None
    assert sel("9.0.1.R01", "OS6860E-P24")[0] is None
    # Exact model family + version applicability (fail closed): no guessing across platforms.
    for version, model in (("8.9.221.R03", ""), ("8.9.221.R03", "OS6450-P24"),
                           ("6.7.2.191.R08", "OS6860E-P24"), ("8.9.221.R03", "OS9999-X")):
        profile, reason = sel(version, model)
        assert profile is None
        assert reason.startswith("Command profile unavailable for this switch model/version")


def test_model_family_extraction():
    assert model_family("OS6860E-P24") == "OS6860"
    assert model_family("OS6860N-P48M") == "OS6860N"
    assert model_family("OS6570M-12") == "OS6570M"
    assert model_family("OS10K") == "OS10K"
    assert model_family("") is None and model_family("Cisco") is None


def test_aos7_profile_is_disabled_and_unverified():
    assert not AOS7_PROFILE.enabled
    assert all(c.verification is Verification.UNVERIFIED for c in AOS7_PROFILE.commands.values())
    with pytest.raises(CommandBlocked):
        FW.accept_profile(AOS7_PROFILE)
    with pytest.raises(CommandBlocked):
        FW.build(CTX, session_id="s", device="SW", operation=Operation.SEARCH_MAC,
                 command_key="mac_lookup", params={"mac": "001122334455"},
                 profile=AOS7_PROFILE)


def test_poe_model_detection():
    assert is_poe_model("OS6450-P24") and is_poe_model("OS6860E-P48")
    assert is_poe_model("OS6560-P48Z16")
    assert not is_poe_model("OS6450-24") and not is_poe_model("OS6900-X20")
