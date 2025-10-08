
#event zeek_init()
#{
#    # Add a new filter to the Conn::LOG stream that logs only
#    # uid and community id
#    local filter: Log::Filter = [$name="some-proto", $path="conn",
#                                $writer=Log::WRITER_REDIS, $include=set("uid", "community_id")];
#    Log::add_filter(Conn::LOG, filter);
#}


@load base/protocols/krb
@load base/protocols/rdp
@load base/protocols/ntlm
@load base/protocols/ldap
@load base/protocols/dce-rpc
@load base/protocols/smb

event zeek_init()
{
    local filter1: Log::Filter = [$name="krb", $path="kerberos", $writer=Log::WRITER_REDISWRITER];
    local filter2: Log::Filter = [$name="rdp", $path="rdp", $writer=Log::WRITER_REDISWRITER];
    local filter3: Log::Filter = [$name="ntlm", $path="ntlm", $writer=Log::WRITER_REDISWRITER];
    local filter4: Log::Filter = [$name="ldap", $path="ldap", $writer=Log::WRITER_REDISWRITER];
    local filter5: Log::Filter = [$name="ldap_search", $path="ldap_search", $writer=Log::WRITER_REDISWRITER];
    local filter6: Log::Filter = [$name="dce_rcp", $path="dce-rpc", $writer=Log::WRITER_REDISWRITER];
    local filter7: Log::Filter = [$name="smb_files", $path="smb_files", $writer=Log::WRITER_REDISWRITER];
    local filter8: Log::Filter = [$name="smb_mapping", $path="smb_mapping", $writer=Log::WRITER_REDISWRITER];


    Log::add_filter(KRB::LOG, filter1);
    Log::add_filter(RDP::LOG, filter2);
    Log::add_filter(NTLM::LOG, filter3);
    Log::add_filter(LDAP::LDAP_LOG, filter4);
    Log::add_filter(LDAP::LDAP_SEARCH_LOG, filter5);
    Log::add_filter(DCE_RPC::LOG, filter6);
    Log::add_filter(SMB::FILES_LOG, filter7);
    Log::add_filter(SMB::MAPPING_LOG, filter8);
}