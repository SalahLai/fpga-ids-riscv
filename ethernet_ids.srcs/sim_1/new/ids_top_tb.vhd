library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity ids_top_tb is
end ids_top_tb;

architecture sim of ids_top_tb is

    constant CLK_PERIOD : time := 20 ns;
    signal led_alert   : std_logic;
    signal clk         : std_logic := '0';
    signal rst         : std_logic := '1';
    signal rmii_crs_dv : std_logic := '0';
    signal rmii_rxd    : std_logic_vector(1 downto 0) := "00";
    signal led_active  : std_logic;
    
    signal alert_syn_fin   : std_logic;
    signal alert_syn_rst   : std_logic;
    signal alert_null_scan : std_logic;
    signal alert_xmas_scan : std_logic;
    signal alert_forbidden : std_logic;
    signal tcp_alert_any   : std_logic;
    
    signal alert_bogon_loop   : std_logic;
    signal alert_bogon_link   : std_logic;
    signal alert_bogon_mcast  : std_logic;
    signal alert_ip_options   : std_logic;
    signal alert_reserved_bit : std_logic;
   
    signal alert_udp_zero_len  : std_logic;
    signal alert_udp_amplify   : std_logic;
    signal alert_udp_land      : std_logic;
    signal alert_udp_oversized : std_logic;
    signal alert_udp_port_zero : std_logic;
    signal alert_udp_ssdp      : std_logic;
    signal alert_udp_memcached : std_logic;

    procedure send_byte (
        constant byte   : in  std_logic_vector(7 downto 0);
        signal   rxd    : out std_logic_vector(1 downto 0);
        signal   crs    : out std_logic;
        constant period : in  time
    ) is
    begin
        crs <= '1';
        rxd <= byte(1 downto 0); wait for period;
        rxd <= byte(3 downto 2); wait for period;
        rxd <= byte(5 downto 4); wait for period;
        rxd <= byte(7 downto 6); wait for period;
    end procedure;

    procedure send_frame (
        signal rxd : out std_logic_vector(1 downto 0);
        signal crs : out std_logic;
        constant period : in time
    ) is
    begin
        -- Preamble
        for i in 0 to 9 loop
            send_byte(x"55", rxd, crs, period);
        end loop;
        -- SFD
        send_byte(x"D5", rxd, crs, period);
        -- Dest MAC
        for i in 0 to 5 loop
            send_byte(x"FF", rxd, crs, period);
        end loop;
        -- Src MAC
        send_byte(x"AA", rxd, crs, period);
        send_byte(x"BB", rxd, crs, period);
        send_byte(x"CC", rxd, crs, period);
        send_byte(x"DD", rxd, crs, period);
        send_byte(x"EE", rxd, crs, period);
        send_byte(x"FF", rxd, crs, period);
        -- EtherType IPv4
        send_byte(x"08", rxd, crs, period);
        send_byte(x"00", rxd, crs, period);
        -- Payload
        send_byte(x"DE", rxd, crs, period);
        send_byte(x"AD", rxd, crs, period);
        -- End of frame
        crs <= '0';
        rxd <= "00";
        wait for 10 * period;
    end procedure;
    procedure send_malformed_frame (
    signal rxd : out std_logic_vector(1 downto 0);
    signal crs : out std_logic;
    constant period : in time
) is
begin
    -- Preamble
    for i in 0 to 9 loop
        send_byte(x"55", rxd, crs, period);
    end loop;
    -- SFD
    send_byte(x"D5", rxd, crs, period);
    -- Dest MAC
    for i in 0 to 5 loop
        send_byte(x"FF", rxd, crs, period);
    end loop;
    -- Src MAC
    send_byte(x"AA", rxd, crs, period);
    send_byte(x"BB", rxd, crs, period);
    send_byte(x"CC", rxd, crs, period);
    send_byte(x"DD", rxd, crs, period);
    send_byte(x"EE", rxd, crs, period);
    send_byte(x"FF", rxd, crs, period);
    -- EtherType IPv4
    send_byte(x"08", rxd, crs, period);
    send_byte(x"00", rxd, crs, period);
    -- IPv4 header — MALFORMED:
    -- Byte 14: version=4, IHL=5 → 0x45 (valid)
    send_byte(x"45", rxd, crs, period);
    -- Byte 15: DSCP/ECN
    send_byte(x"00", rxd, crs, period);
    -- Bytes 16-17: Total length = 5 → TOO SMALL (triggers R3)
    send_byte(x"00", rxd, crs, period);
    send_byte(x"05", rxd, crs, period);
    -- Bytes 18-19: Identification
    send_byte(x"00", rxd, crs, period);
    send_byte(x"00", rxd, crs, period);
    -- Bytes 20-21: Flags=0, Frag offset=100 → FRAGMENT (triggers R5)
    send_byte(x"00", rxd, crs, period);
    send_byte(x"64", rxd, crs, period);
    -- Byte 22: TTL = 1 → LOW TTL (triggers R4)
    send_byte(x"01", rxd, crs, period);
    -- Byte 23: Protocol = TCP
    send_byte(x"06", rxd, crs, period);
    -- Bytes 24-25: Checksum
    send_byte(x"00", rxd, crs, period);
    send_byte(x"00", rxd, crs, period);
    -- Bytes 26-29: Src IP = 0.0.0.0 → SPOOFED (triggers R6)
    send_byte(x"00", rxd, crs, period);
    send_byte(x"00", rxd, crs, period);
    send_byte(x"00", rxd, crs, period);
    send_byte(x"00", rxd, crs, period);
    -- Bytes 30-33: Dst IP = 192.168.1.1
    send_byte(x"C0", rxd, crs, period);
    send_byte(x"A8", rxd, crs, period);
    send_byte(x"01", rxd, crs, period);
    send_byte(x"01", rxd, crs, period);
    -- End of frame
    crs <= '0';
    rxd <= "00";
    wait for 10 * period;
end procedure;

procedure send_ipv4_frame (
    constant src_ip  : in std_logic_vector(31 downto 0);
    constant dst_ip  : in std_logic_vector(31 downto 0);
    constant ihl     : in std_logic_vector(3 downto 0);
    constant length  : in std_logic_vector(15 downto 0);
    constant ttl     : in std_logic_vector(7 downto 0);
    constant flags   : in std_logic_vector(2 downto 0);
    signal   rxd     : out std_logic_vector(1 downto 0);
    signal   crs     : out std_logic;
    constant period  : in time
) is
    variable byte14 : std_logic_vector(7 downto 0);
    variable byte20 : std_logic_vector(7 downto 0);
begin
    -- Preamble
    for i in 0 to 9 loop
        send_byte(x"55", rxd, crs, period);
    end loop;
    send_byte(x"D5", rxd, crs, period);
    -- Dest MAC
    for i in 0 to 5 loop
        send_byte(x"FF", rxd, crs, period);
    end loop;
    -- Src MAC
    send_byte(x"AA", rxd, crs, period);
    send_byte(x"BB", rxd, crs, period);
    send_byte(x"CC", rxd, crs, period);
    send_byte(x"DD", rxd, crs, period);
    send_byte(x"EE", rxd, crs, period);
    send_byte(x"FF", rxd, crs, period);
    -- EtherType IPv4
    send_byte(x"08", rxd, crs, period);
    send_byte(x"00", rxd, crs, period);
    -- Byte 14: Version + IHL
    byte14 := x"4" & ihl;
    send_byte(byte14, rxd, crs, period);
    -- Byte 15: DSCP
    send_byte(x"00", rxd, crs, period);
    -- Bytes 16-17: Total length
    send_byte(length(15 downto 8), rxd, crs, period);
    send_byte(length(7 downto 0),  rxd, crs, period);
    -- Bytes 18-19: ID
    send_byte(x"00", rxd, crs, period);
    send_byte(x"00", rxd, crs, period);
    -- Byte 20: Flags + frag offset high
    byte20 := flags & "00000";
    send_byte(byte20, rxd, crs, period);
    -- Byte 21: Frag offset low
    send_byte(x"00", rxd, crs, period);
    -- Byte 22: TTL
    send_byte(ttl, rxd, crs, period);
    -- Byte 23: Protocol = TCP
    send_byte(x"06", rxd, crs, period);
    -- Bytes 24-25: Checksum
    send_byte(x"00", rxd, crs, period);
    send_byte(x"00", rxd, crs, period);
    -- Bytes 26-29: Source IP
    send_byte(src_ip(31 downto 24), rxd, crs, period);
    send_byte(src_ip(23 downto 16), rxd, crs, period);
    send_byte(src_ip(15 downto 8),  rxd, crs, period);
    send_byte(src_ip(7 downto 0),   rxd, crs, period);
    -- Bytes 30-33: Dest IP
    send_byte(dst_ip(31 downto 24), rxd, crs, period);
    send_byte(dst_ip(23 downto 16), rxd, crs, period);
    send_byte(dst_ip(15 downto 8),  rxd, crs, period);
    send_byte(dst_ip(7 downto 0),   rxd, crs, period);
    -- Minimal TCP header (20 bytes)
    for i in 0 to 19 loop
        send_byte(x"00", rxd, crs, period);
    end loop;
    -- End of frame
    crs <= '0';
    rxd <= "00";
    wait for 10 * period;
end procedure;



procedure send_tcp_frame (
    constant flags  : in std_logic_vector(7 downto 0);
    constant dport  : in std_logic_vector(15 downto 0);
    constant sport  : in std_logic_vector(15 downto 0);
    signal   rxd    : out std_logic_vector(1 downto 0);
    signal   crs    : out std_logic;
    constant period : in time
) is
begin
    -- Preamble
    for i in 0 to 9 loop
        send_byte(x"55", rxd, crs, period);
    end loop;
    -- SFD
    send_byte(x"D5", rxd, crs, period);
    -- Dest MAC
    for i in 0 to 5 loop
        send_byte(x"FF", rxd, crs, period);
    end loop;
    -- Src MAC
    send_byte(x"AA", rxd, crs, period);
    send_byte(x"BB", rxd, crs, period);
    send_byte(x"CC", rxd, crs, period);
    send_byte(x"DD", rxd, crs, period);
    send_byte(x"EE", rxd, crs, period);
    send_byte(x"FF", rxd, crs, period);
    -- EtherType IPv4
    send_byte(x"08", rxd, crs, period);
    send_byte(x"00", rxd, crs, period);
    -- IPv4 header (valid, IHL=5, protocol=0x06 TCP)
    send_byte(x"45", rxd, crs, period);  -- version=4, IHL=5
    send_byte(x"00", rxd, crs, period);  -- DSCP
    send_byte(x"00", rxd, crs, period);  -- length high
    send_byte(x"28", rxd, crs, period);  -- length low = 40
    send_byte(x"00", rxd, crs, period);  -- ID high
    send_byte(x"00", rxd, crs, period);  -- ID low
    send_byte(x"00", rxd, crs, period);  -- flags + frag high
    send_byte(x"00", rxd, crs, period);  -- frag low
    send_byte(x"40", rxd, crs, period);  -- TTL = 64
    send_byte(x"06", rxd, crs, period);  -- protocol = TCP
    send_byte(x"00", rxd, crs, period);  -- checksum high
    send_byte(x"00", rxd, crs, period);  -- checksum low
    send_byte(x"C0", rxd, crs, period);  -- src IP = 192.168.1.1
    send_byte(x"A8", rxd, crs, period);
    send_byte(x"01", rxd, crs, period);
    send_byte(x"01", rxd, crs, period);
    send_byte(x"C0", rxd, crs, period);  -- dst IP = 192.168.1.2
    send_byte(x"A8", rxd, crs, period);
    send_byte(x"01", rxd, crs, period);
    send_byte(x"02", rxd, crs, period);
    -- TCP header
    send_byte(sport(15 downto 8), rxd, crs, period);  -- src port high
    send_byte(sport(7 downto 0),  rxd, crs, period);  -- src port low
    send_byte(dport(15 downto 8), rxd, crs, period);  -- dst port high
    send_byte(dport(7 downto 0),  rxd, crs, period);  -- dst port low
    send_byte(x"00", rxd, crs, period);  -- seq byte 0
    send_byte(x"00", rxd, crs, period);  -- seq byte 1
    send_byte(x"00", rxd, crs, period);  -- seq byte 2
    send_byte(x"01", rxd, crs, period);  -- seq byte 3
    send_byte(x"00", rxd, crs, period);  -- ack byte 0
    send_byte(x"00", rxd, crs, period);  -- ack byte 1
    send_byte(x"00", rxd, crs, period);  -- ack byte 2
    send_byte(x"00", rxd, crs, period);  -- ack byte 3
    send_byte(x"50", rxd, crs, period);  -- data offset = 5
    send_byte(flags,  rxd, crs, period); -- FLAGS (passed in)
    send_byte(x"FF", rxd, crs, period);  -- window size high
    send_byte(x"FF", rxd, crs, period);  -- window size low
    send_byte(x"00", rxd, crs, period);  -- checksum high
    send_byte(x"00", rxd, crs, period);  -- checksum low
    send_byte(x"00", rxd, crs, period);  -- urgent pointer high
    send_byte(x"00", rxd, crs, period);  -- urgent pointer low
    -- End of frame
    crs <= '0';
    rxd <= "00";
    wait for 10 * period;
end procedure;

procedure send_udp_frame (
    constant src_ip   : in std_logic_vector(31 downto 0);
    constant dst_ip   : in std_logic_vector(31 downto 0);
    constant sport    : in std_logic_vector(15 downto 0);
    constant dport    : in std_logic_vector(15 downto 0);
    constant udp_len  : in std_logic_vector(15 downto 0);
    signal   rxd      : out std_logic_vector(1 downto 0);
    signal   crs      : out std_logic;
    constant period   : in time
) is
begin
    -- Preamble + SFD
    for i in 0 to 9 loop
        send_byte(x"55", rxd, crs, period);
    end loop;
    send_byte(x"D5", rxd, crs, period);
    -- Dest MAC
    for i in 0 to 5 loop
        send_byte(x"FF", rxd, crs, period);
    end loop;
    -- Src MAC
    send_byte(x"AA", rxd, crs, period);
    send_byte(x"BB", rxd, crs, period);
    send_byte(x"CC", rxd, crs, period);
    send_byte(x"DD", rxd, crs, period);
    send_byte(x"EE", rxd, crs, period);
    send_byte(x"FF", rxd, crs, period);
    -- EtherType IPv4
    send_byte(x"08", rxd, crs, period);
    send_byte(x"00", rxd, crs, period);
    -- IPv4 header (IHL=5, protocol=0x11 UDP)
    send_byte(x"45", rxd, crs, period);
    send_byte(x"00", rxd, crs, period);
    send_byte(x"00", rxd, crs, period);
    send_byte(x"1C", rxd, crs, period);  -- total length = 28 (20 IP + 8 UDP)
    send_byte(x"00", rxd, crs, period);
    send_byte(x"00", rxd, crs, period);
    send_byte(x"00", rxd, crs, period);
    send_byte(x"00", rxd, crs, period);
    send_byte(x"40", rxd, crs, period);  -- TTL = 64
    send_byte(x"11", rxd, crs, period);  -- protocol = 17 (UDP)
    send_byte(x"00", rxd, crs, period);
    send_byte(x"00", rxd, crs, period);
    -- Src IP
    send_byte(src_ip(31 downto 24), rxd, crs, period);
    send_byte(src_ip(23 downto 16), rxd, crs, period);
    send_byte(src_ip(15 downto 8),  rxd, crs, period);
    send_byte(src_ip(7 downto 0),   rxd, crs, period);
    -- Dst IP
    send_byte(dst_ip(31 downto 24), rxd, crs, period);
    send_byte(dst_ip(23 downto 16), rxd, crs, period);
    send_byte(dst_ip(15 downto 8),  rxd, crs, period);
    send_byte(dst_ip(7 downto 0),   rxd, crs, period);
    -- UDP header
    send_byte(sport(15 downto 8), rxd, crs, period);
    send_byte(sport(7 downto 0),  rxd, crs, period);
    send_byte(dport(15 downto 8), rxd, crs, period);
    send_byte(dport(7 downto 0),  rxd, crs, period);
    send_byte(udp_len(15 downto 8), rxd, crs, period);
    send_byte(udp_len(7 downto 0),  rxd, crs, period);
    send_byte(x"00", rxd, crs, period);  -- checksum
    send_byte(x"00", rxd, crs, period);
    -- End of frame
    crs <= '0';
    rxd <= "00";
    wait for 10 * period;
end procedure;


begin

    clk <= not clk after CLK_PERIOD / 2;

    uut : entity work.ids_top
        generic map (CLK_FREQ_HZ => 1000)
        port map (
            clk         => clk,
            rst         => rst,
            rmii_crs_dv => rmii_crs_dv,
            rmii_rxd    => rmii_rxd,
            led_active  => led_active,
            led_alert   => led_alert
        );

    process
    begin
        rst <= '1';
        wait for 5 * CLK_PERIOD;
        rst <= '0';
        wait for 2 * CLK_PERIOD;
    
        -- Test 1: Clean SYN packet (flags=0x02) to port 80
        -- Expected: no alerts
        send_tcp_frame(x"02", x"0050", x"C000", rmii_rxd, rmii_crs_dv, CLK_PERIOD);
        wait for 5 * CLK_PERIOD;
    
        -- Test 2: SYN+FIN attack (flags=0x03)
        -- Expected: alert_syn_fin fires
        send_tcp_frame(x"03", x"0050", x"C001", rmii_rxd, rmii_crs_dv, CLK_PERIOD);
        wait for 5 * CLK_PERIOD;
    
        -- Test 3: NULL scan (flags=0x00)
        -- Expected: alert_null_scan fires
        send_tcp_frame(x"00", x"0050", x"C002", rmii_rxd, rmii_crs_dv, CLK_PERIOD);
        wait for 5 * CLK_PERIOD;
    
        -- Test 4: XMAS scan (flags=0xFF)
        -- Expected: alert_xmas_scan fires
        send_tcp_frame(x"FF", x"0050", x"C003", rmii_rxd, rmii_crs_dv, CLK_PERIOD);
        wait for 5 * CLK_PERIOD;
    
        -- Test 5: Telnet access (dst port=23, flags=0x02)
        -- Expected: alert_forbidden fires
        send_tcp_frame(x"02", x"0017", x"C004", rmii_rxd, rmii_crs_dv, CLK_PERIOD);
        wait for 5 * CLK_PERIOD;
    
        -- Test 6: SYN+RST (flags=0x06)
        -- Expected: alert_syn_rst fires
        send_tcp_frame(x"06", x"0050", x"C005", rmii_rxd, rmii_crs_dv, CLK_PERIOD);
        wait for 5 * CLK_PERIOD;
        
        wait for 5 * CLK_PERIOD;

        -- Test R8: Bogon loopback source (127.0.0.1)
        -- Expected: alert_bogon_loop fires
        send_ipv4_frame(
            src_ip => x"7F000001",
            dst_ip => x"C0A80102",
            ihl    => x"5",
            length => x"0028",
            ttl    => x"40",
            flags  => "000",
            rxd => rmii_rxd, crs => rmii_crs_dv, period => CLK_PERIOD
        );
        wait for 5 * CLK_PERIOD;

        -- Test R9: Bogon link-local source (169.254.1.1)
        -- Expected: alert_bogon_link fires
        send_ipv4_frame(
            src_ip => x"A9FE0101",
            dst_ip => x"C0A80102",
            ihl    => x"5",
            length => x"0028",
            ttl    => x"40",
            flags  => "000",
            rxd => rmii_rxd, crs => rmii_crs_dv, period => CLK_PERIOD
        );
        wait for 5 * CLK_PERIOD;

        -- Test R10: Bogon multicast source (224.0.0.1)
        -- Expected: alert_bogon_mcast fires
        send_ipv4_frame(
            src_ip => x"E0000001",
            dst_ip => x"C0A80102",
            ihl    => x"5",
            length => x"0028",
            ttl    => x"40",
            flags  => "000",
            rxd => rmii_rxd, crs => rmii_crs_dv, period => CLK_PERIOD
        );
        wait for 5 * CLK_PERIOD;

        -- Test R11: IP options present (IHL = 6)
        -- Expected: alert_ip_options fires
        send_ipv4_frame(
            src_ip => x"C0A80101",
            dst_ip => x"C0A80102",
            ihl    => x"6",
            length => x"002C",
            ttl    => x"40",
            flags  => "000",
            rxd => rmii_rxd, crs => rmii_crs_dv, period => CLK_PERIOD
        );
        wait for 5 * CLK_PERIOD;

        -- Test R12: Reserved bit set (flags = "100")
        -- Expected: alert_reserved_bit fires
        send_ipv4_frame(
            src_ip => x"C0A80101",
            dst_ip => x"C0A80102",
            ihl    => x"5",
            length => x"0028",
            ttl    => x"40",
            flags  => "100",
            rxd => rmii_rxd, crs => rmii_crs_dv, period => CLK_PERIOD
        );
        wait for 5 * CLK_PERIOD;
        -- ── UDP TESTS ─────────────────────────────────────────────

        -- Test U1: Forbidden dst port (DNS = 53 = 0x0035)
        -- Expected: alert_udp_forbidden fires
        send_udp_frame(
            src_ip  => x"C0A80101",
            dst_ip  => x"C0A80102",
            sport   => x"C000",
            dport   => x"0035",
            udp_len => x"0008",
            rxd => rmii_rxd, crs => rmii_crs_dv, period => CLK_PERIOD
        );
        wait for 5 * CLK_PERIOD;

        -- Test U2: UDP length < 8 (impossible)
        -- Expected: alert_udp_short fires
        send_udp_frame(
            src_ip  => x"C0A80101",
            dst_ip  => x"C0A80102",
            sport   => x"C001",
            dport   => x"0050",
            udp_len => x"0004",
            rxd => rmii_rxd, crs => rmii_crs_dv, period => CLK_PERIOD
        );
        wait for 5 * CLK_PERIOD;

        -- Test U3: UDP length = 0
        -- Expected: alert_udp_zero_len fires
        send_udp_frame(
            src_ip  => x"C0A80101",
            dst_ip  => x"C0A80102",
            sport   => x"C002",
            dport   => x"0050",
            udp_len => x"0000",
            rxd => rmii_rxd, crs => rmii_crs_dv, period => CLK_PERIOD
        );
        wait for 5 * CLK_PERIOD;

        -- Test U4: Amplification attack response (src port = NTP = 123 = 0x007B)
        -- Expected: alert_udp_amplify fires
        send_udp_frame(
            src_ip  => x"0A000001",
            dst_ip  => x"C0A80101",
            sport   => x"007B",
            dport   => x"C003",
            udp_len => x"0008",
            rxd => rmii_rxd, crs => rmii_crs_dv, period => CLK_PERIOD
        );
        wait for 5 * CLK_PERIOD;

        -- Test U5: UDP Land attack (src IP+port = dst IP+port)
        -- Expected: alert_udp_land fires
        send_udp_frame(
            src_ip  => x"C0A80101",
            dst_ip  => x"C0A80101",
            sport   => x"1234",
            dport   => x"1234",
            udp_len => x"0008",
            rxd => rmii_rxd, crs => rmii_crs_dv, period => CLK_PERIOD
        );
        wait for 5 * CLK_PERIOD;

        -- Test U6: Oversized UDP (length > 1472 = 0x05C0)
        -- Expected: alert_udp_oversized fires
        send_udp_frame(
            src_ip  => x"C0A80101",
            dst_ip  => x"C0A80102",
            sport   => x"C004",
            dport   => x"0050",
            udp_len => x"05DC",
            rxd => rmii_rxd, crs => rmii_crs_dv, period => CLK_PERIOD
        );
        wait for 5 * CLK_PERIOD;

        -- Test U7: Port zero (src port = 0)
        -- Expected: alert_udp_port_zero fires
        send_udp_frame(
            src_ip  => x"C0A80101",
            dst_ip  => x"C0A80102",
            sport   => x"0000",
            dport   => x"0050",
            udp_len => x"0008",
            rxd => rmii_rxd, crs => rmii_crs_dv, period => CLK_PERIOD
        );
        wait for 5 * CLK_PERIOD;

        -- Test U8: SSDP abuse (dst port = 1900 = 0x076C)
        -- Expected: alert_udp_ssdp fires
        send_udp_frame(
            src_ip  => x"C0A80101",
            dst_ip  => x"C0A80102",
            sport   => x"C005",
            dport   => x"076C",
            udp_len => x"0008",
            rxd => rmii_rxd, crs => rmii_crs_dv, period => CLK_PERIOD
        );
        wait for 5 * CLK_PERIOD;

        -- Test U9: Memcached amplification (port 11211 = 0x2BCB)
        -- Expected: alert_udp_memcached fires
        send_udp_frame(
            src_ip  => x"C0A80101",
            dst_ip  => x"C0A80102",
            sport   => x"C006",
            dport   => x"2BCB",
            udp_len => x"0008",
            rxd => rmii_rxd, crs => rmii_crs_dv, period => CLK_PERIOD
        );
        wait for 5 * CLK_PERIOD;

        wait;
    end process;
end sim;
