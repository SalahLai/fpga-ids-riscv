library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity axis_ids_top is
    generic (CLK_FREQ_HZ : integer := 50_000_000);
    port (
        clk           : in  std_logic;
        rst           : in  std_logic;
        -- AXI-Stream input (from PS via DMA)
        s_axis_tdata  : in  std_logic_vector(7 downto 0);
        s_axis_tvalid : in  std_logic;
        s_axis_tlast  : in  std_logic;
        s_axis_tready : out std_logic;
        -- Outputs
        led_active    : out std_logic;
        led_alert     : out std_logic;
        -- Individual alert flags (for future scoring engine)
        alert_bad_version  : out std_logic;
        alert_bad_ihl      : out std_logic;
        alert_bad_length   : out std_logic;
        alert_low_ttl      : out std_logic;
        alert_fragment     : out std_logic;
        alert_spoof_src    : out std_logic;
        alert_land_attack  : out std_logic;
        alert_syn_fin      : out std_logic;
        alert_syn_rst      : out std_logic;
        alert_null_scan    : out std_logic;
        alert_xmas_scan    : out std_logic;
        alert_forbidden    : out std_logic
    );
end axis_ids_top;

architecture rtl of axis_ids_top is
    -- Byte stream
    signal rx_byte        : std_logic_vector(7 downto 0);
    signal rx_valid       : std_logic;
    signal rx_sof         : std_logic;
    signal rx_eof         : std_logic;
    -- Ethernet parser
    signal frame_done     : std_logic;
    signal is_ipv4        : std_logic;
    signal is_arp         : std_logic;
    signal is_unknown     : std_logic;
    -- IPv4 parser
    signal ip_parse_done  : std_logic;
    signal ip_parse_valid : std_logic;
    signal ip_version     : std_logic_vector(3 downto 0);
    signal ip_ihl         : std_logic_vector(3 downto 0);
    signal ip_length      : std_logic_vector(15 downto 0);
    signal ip_flags       : std_logic_vector(2 downto 0);
    signal ip_frag_off    : std_logic_vector(12 downto 0);
    signal ip_ttl         : std_logic_vector(7 downto 0);
    signal ip_protocol    : std_logic_vector(7 downto 0);
    signal ip_src         : std_logic_vector(31 downto 0);
    signal ip_dst         : std_logic_vector(31 downto 0);
    -- IPv4 checker alerts
    signal alert_bad_version_i  : std_logic;
    signal alert_bad_ihl_i      : std_logic;
    signal alert_bad_length_i   : std_logic;
    signal alert_low_ttl_i      : std_logic;
    signal alert_fragment_i     : std_logic;
    signal alert_spoof_src_i    : std_logic;
    signal alert_land_attack_i  : std_logic;
    signal alert_ipv4_any       : std_logic;
    -- TCP checker alerts
    signal alert_syn_fin_i      : std_logic;
    signal alert_syn_rst_i      : std_logic;
    signal alert_null_scan_i    : std_logic;
    signal alert_xmas_scan_i    : std_logic;
    signal alert_forbidden_i    : std_logic;
    signal alert_tcp_any        : std_logic;
    -- Alert latch
    signal alert_latch          : std_logic := '0';signal tcp_src_port_i : std_logic_vector(15 downto 0);
    signal tcp_dst_port_i : std_logic_vector(15 downto 0);
    signal tcp_flags_i    : std_logic_vector(7 downto 0);
    signal tcp_parse_done_i  : std_logic;
    signal tcp_parse_valid_i : std_logic;
    
begin

    u_axis_rx : entity work.axis_rx
        port map (
            clk           => clk,
            rst           => rst,
            s_axis_tdata  => s_axis_tdata,
            s_axis_tvalid => s_axis_tvalid,
            s_axis_tlast  => s_axis_tlast,
            s_axis_tready => s_axis_tready,
            rx_byte       => rx_byte,
            rx_valid      => rx_valid,
            rx_sof        => rx_sof,
            rx_eof        => rx_eof
        );

    u_eth_parser : entity work.eth_parser
        port map (
            clk        => clk, rst => rst,
            rx_byte    => rx_byte, rx_valid => rx_valid,
            rx_sof     => rx_sof, rx_eof => rx_eof,
            frame_done => frame_done,
            is_ipv4    => is_ipv4, is_arp => is_arp, is_unknown => is_unknown,
            dst_mac => open, src_mac => open, ethertype => open
        );

    u_frame_counter : entity work.frame_counter
        generic map (CLK_FREQ_HZ => CLK_FREQ_HZ)
        port map (
            clk => clk, rst => rst,
            frame_done => frame_done,
            is_ipv4 => is_ipv4, is_arp => is_arp, is_unknown => is_unknown,
            fps_total => open, fps_ipv4 => open,
            fps_arp => open, fps_unknown => open,
            led_active => led_active
        );

    u_ipv4_parser : entity work.ipv4_parser
        port map (
            clk => clk, rst => rst,
            rx_byte => rx_byte, rx_valid => rx_valid,
            rx_sof => rx_sof, rx_eof => rx_eof,
            ip_version => ip_version, ip_ihl => ip_ihl,
            ip_length => ip_length, ip_flags => ip_flags,
            ip_frag_off => ip_frag_off, ip_ttl => ip_ttl,
            ip_protocol => ip_protocol,
            ip_src => ip_src, ip_dst => ip_dst,
            parse_done => ip_parse_done, parse_valid => ip_parse_valid
        );

    u_ipv4_checker : entity work.ipv4_checker
        port map (
            clk => clk, rst => rst,
            parse_done => ip_parse_done, parse_valid => ip_parse_valid,
            ip_version => ip_version, ip_ihl => ip_ihl,
            ip_length => ip_length, ip_flags => ip_flags,
            ip_frag_off => ip_frag_off, ip_ttl => ip_ttl,
            ip_protocol => ip_protocol,
            ip_src => ip_src, ip_dst => ip_dst,
            alert_bad_version => alert_bad_version_i,
            alert_bad_ihl     => alert_bad_ihl_i,
            alert_bad_length  => alert_bad_length_i,
            alert_low_ttl     => alert_low_ttl_i,
            alert_fragment    => alert_fragment_i,
            alert_spoof_src   => alert_spoof_src_i,
            alert_land_attack => alert_land_attack_i,
            alert_any         => alert_ipv4_any
        );

    u_tcp_parser : entity work.tcp_parser
    port map (
        clk          => clk, rst => rst,
        rx_byte      => rx_byte, rx_valid => rx_valid,
        rx_sof       => rx_sof, rx_eof => rx_eof,
        ip_protocol  => ip_protocol, ip_ihl => ip_ihl,
        ip_valid     => ip_parse_done,
        tcp_src_port => tcp_src_port_i,
        tcp_dst_port => tcp_dst_port_i,
        tcp_flags    => tcp_flags_i,
        tcp_seq      => open,
        parse_done   => tcp_parse_done_i,
        parse_valid  => tcp_parse_valid_i
    );

    u_tcp_checker : entity work.tcp_checker
    port map (
        clk          => clk, rst => rst,
        parse_done   => tcp_parse_done_i,
        parse_valid  => tcp_parse_valid_i,
        tcp_src_port => tcp_src_port_i,
        tcp_dst_port => tcp_dst_port_i,
        tcp_flags    => tcp_flags_i,
        alert_syn_fin   => alert_syn_fin_i,
        alert_syn_rst   => alert_syn_rst_i,
        alert_null_scan => alert_null_scan_i,
        alert_xmas_scan => alert_xmas_scan_i,
        alert_forbidden => alert_forbidden_i,
        alert_any       => alert_tcp_any
    );

    -- Drive output ports from internal signals
    alert_bad_version <= alert_bad_version_i;
    alert_bad_ihl     <= alert_bad_ihl_i;
    alert_bad_length  <= alert_bad_length_i;
    alert_low_ttl     <= alert_low_ttl_i;
    alert_fragment    <= alert_fragment_i;
    alert_spoof_src   <= alert_spoof_src_i;
    alert_land_attack <= alert_land_attack_i;
    alert_syn_fin     <= alert_syn_fin_i;
    alert_syn_rst     <= alert_syn_rst_i;
    alert_null_scan   <= alert_null_scan_i;
    alert_xmas_scan   <= alert_xmas_scan_i;
    alert_forbidden   <= alert_forbidden_i;

    -- Latch any alert → LED
    process(clk)
    begin
        if rising_edge(clk) then
            if rst = '1' then
                alert_latch <= '0';
            elsif alert_ipv4_any = '1' or alert_tcp_any = '1' then
                alert_latch <= '1';
            end if;
        end if;
    end process;

    led_alert <= alert_latch;

end rtl;