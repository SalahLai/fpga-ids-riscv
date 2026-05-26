library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity ids_top is
    generic (
        CLK_FREQ_HZ : integer := 50_000_000
    );
    port (
        clk         : in  std_logic;
        rst         : in  std_logic;
        -- RMII PHY pins
        rmii_crs_dv : in  std_logic;
        rmii_rxd    : in  std_logic_vector(1 downto 0);
        -- Outputs
        led_active  : out std_logic;
        led_alert   : out std_logic;   -- lights up when any IDS alert fires
        -- TCP alert outputs (for testbench visibility)
        alert_syn_fin   : out std_logic;
        alert_syn_rst   : out std_logic;
        alert_null_scan : out std_logic;
        alert_xmas_scan : out std_logic;
        alert_forbidden : out std_logic;
        tcp_alert_any   : out std_logic
    );
end ids_top;

architecture rtl of ids_top is

    -- rmii_rx → eth_parser + ipv4_parser
    signal rx_byte   : std_logic_vector(7 downto 0);
    signal rx_valid  : std_logic;
    signal rx_sof    : std_logic;
    signal rx_eof    : std_logic;

    -- eth_parser outputs
    signal frame_done  : std_logic;
    signal is_ipv4     : std_logic;
    signal is_arp      : std_logic;
    signal is_unknown  : std_logic;

    -- ipv4_parser outputs
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

    -- ipv4_checker outputs
    signal alert_bad_version  : std_logic;
    signal alert_bad_ihl      : std_logic;
    signal alert_bad_length   : std_logic;
    signal alert_low_ttl      : std_logic;
    signal alert_fragment     : std_logic;
    signal alert_spoof_src    : std_logic;
    signal alert_land_attack  : std_logic;
    signal alert_any          : std_logic;

    -- Alert latch (keeps LED on for visibility)
    signal alert_latch : std_logic := '0';
    
    -- tcp_parser outputs
    signal tcp_src_port    : std_logic_vector(15 downto 0);
    signal tcp_dst_port    : std_logic_vector(15 downto 0);
    signal tcp_flags       : std_logic_vector(7 downto 0);
    signal tcp_seq         : std_logic_vector(31 downto 0);
    signal tcp_parse_done  : std_logic;
    signal tcp_parse_valid : std_logic;
    signal tcp_alert_any_i : std_logic;
begin

    -- Layer 1: RMII Receiver
    u_rmii_rx : entity work.rmii_rx
        port map (
            clk         => clk,
            rst         => rst,
            rmii_crs_dv => rmii_crs_dv,
            rmii_rxd    => rmii_rxd,
            rx_byte     => rx_byte,
            rx_valid    => rx_valid,
            rx_sof      => rx_sof,
            rx_eof      => rx_eof
        );

    -- Layer 2a: Ethernet Parser
    u_eth_parser : entity work.eth_parser
        port map (
            clk        => clk,
            rst        => rst,
            rx_byte    => rx_byte,
            rx_valid   => rx_valid,
            rx_sof     => rx_sof,
            rx_eof     => rx_eof,
            frame_done => frame_done,
            is_ipv4    => is_ipv4,
            is_arp     => is_arp,
            is_unknown => is_unknown,
            dst_mac    => open,
            src_mac    => open,
            ethertype  => open
        );

    -- Layer 2b: Frame Counter
    u_frame_counter : entity work.frame_counter
        generic map (CLK_FREQ_HZ => CLK_FREQ_HZ)
        port map (
            clk         => clk,
            rst         => rst,
            frame_done  => frame_done,
            is_ipv4     => is_ipv4,
            is_arp      => is_arp,
            is_unknown  => is_unknown,
            fps_total   => open,
            fps_ipv4    => open,
            fps_arp     => open,
            fps_unknown => open,
            led_active  => led_active
        );

    -- Layer 3a: IPv4 Parser
    -- Runs in parallel with eth_parser on same byte stream
    u_ipv4_parser : entity work.ipv4_parser
        port map (
            clk         => clk,
            rst         => rst,
            rx_byte     => rx_byte,
            rx_valid    => rx_valid,
            rx_sof      => rx_sof,
            rx_eof      => rx_eof,
            ip_version  => ip_version,
            ip_ihl      => ip_ihl,
            ip_length   => ip_length,
            ip_flags    => ip_flags,
            ip_frag_off => ip_frag_off,
            ip_ttl      => ip_ttl,
            ip_protocol => ip_protocol,
            ip_src      => ip_src,
            ip_dst      => ip_dst,
            parse_done  => ip_parse_done,
            parse_valid => ip_parse_valid
        );

    -- Layer 3b: IPv4 Checker (IDS Rules)
    u_ipv4_checker : entity work.ipv4_checker
        port map (
            clk               => clk,
            rst               => rst,
            parse_done        => ip_parse_done,
            parse_valid       => ip_parse_valid,
            ip_version        => ip_version,
            ip_ihl            => ip_ihl,
            ip_length         => ip_length,
            ip_flags          => ip_flags,
            ip_frag_off       => ip_frag_off,
            ip_ttl            => ip_ttl,
            ip_protocol       => ip_protocol,
            ip_src            => ip_src,
            ip_dst            => ip_dst,
            alert_bad_version => alert_bad_version,
            alert_bad_ihl     => alert_bad_ihl,
            alert_bad_length  => alert_bad_length,
            alert_low_ttl     => alert_low_ttl,
            alert_fragment    => alert_fragment,
            alert_spoof_src   => alert_spoof_src,
            alert_land_attack => alert_land_attack,
            alert_any         => alert_any
        );
        -- Layer 4a: TCP Parser
u_tcp_parser : entity work.tcp_parser
    port map (
        clk         => clk,
        rst         => rst,
        rx_byte     => rx_byte,
        rx_valid    => rx_valid,
        rx_sof      => rx_sof,
        rx_eof      => rx_eof,
        ip_protocol => ip_protocol,
        ip_ihl      => ip_ihl,
        ip_valid    => ip_parse_done,
        tcp_src_port => tcp_src_port,
        tcp_dst_port => tcp_dst_port,
        tcp_flags    => tcp_flags,
        tcp_seq      => tcp_seq,
        parse_done   => tcp_parse_done,
        parse_valid  => tcp_parse_valid
    );

-- Layer 4b: TCP Checker
u_tcp_checker : entity work.tcp_checker
    port map (
        clk            => clk,
        rst            => rst,
        parse_done     => tcp_parse_done,
        parse_valid    => tcp_parse_valid,
        tcp_src_port   => tcp_src_port,
        tcp_dst_port   => tcp_dst_port,
        tcp_flags      => tcp_flags,
        alert_syn_fin   => alert_syn_fin,
        alert_syn_rst   => alert_syn_rst,
        alert_null_scan => alert_null_scan,
        alert_xmas_scan => alert_xmas_scan,
        alert_forbidden => alert_forbidden,
        alert_any       => tcp_alert_any_i
    );  
    tcp_alert_any <= tcp_alert_any_i;
    -- Alert latch: once an alert fires, LED stays on
    -- Reset clears it
  process(clk)
    begin
        if rising_edge(clk) then
            if rst = '1' then
                alert_latch <= '0';
            elsif alert_any = '1' or tcp_alert_any_i = '1' then
                alert_latch <= '1';
            end if;
        end if;
    end process;
    
    led_alert <= alert_latch;

end rtl;