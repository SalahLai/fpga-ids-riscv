library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity ipv4_checker_tb is
end ipv4_checker_tb;

architecture sim of ipv4_checker_tb is

    constant CLK_PERIOD : time := 20 ns;

    signal clk         : std_logic := '0';
    signal rst         : std_logic := '1';
    signal parse_done  : std_logic := '0';
    signal parse_valid : std_logic := '0';

    -- Parser outputs (inputs to checker)
    signal ip_version  : std_logic_vector(3 downto 0)  := x"4";
    signal ip_ihl      : std_logic_vector(3 downto 0)  := x"5";
    signal ip_length   : std_logic_vector(15 downto 0) := x"0028";
    signal ip_flags    : std_logic_vector(2 downto 0)  := "000";
    signal ip_frag_off : std_logic_vector(12 downto 0) := (others => '0');
    signal ip_ttl      : std_logic_vector(7 downto 0)  := x"40";
    signal ip_protocol : std_logic_vector(7 downto 0)  := x"06";
    signal ip_src      : std_logic_vector(31 downto 0) := x"C0A80101";
    signal ip_dst      : std_logic_vector(31 downto 0) := x"C0A80102";

    -- Alert outputs
    signal alert_bad_version : std_logic;
    signal alert_bad_ihl     : std_logic;
    signal alert_bad_length  : std_logic;
    signal alert_low_ttl     : std_logic;
    signal alert_fragment    : std_logic;
    signal alert_spoof_src   : std_logic;
    signal alert_land_attack : std_logic;
    signal alert_any         : std_logic;

    -- Component
    component ipv4_checker
        port (
            clk               : in  std_logic;
            rst               : in  std_logic;
            parse_done        : in  std_logic;
            parse_valid       : in  std_logic;
            ip_version        : in  std_logic_vector(3 downto 0);
            ip_ihl            : in  std_logic_vector(3 downto 0);
            ip_length         : in  std_logic_vector(15 downto 0);
            ip_flags          : in  std_logic_vector(2 downto 0);
            ip_frag_off       : in  std_logic_vector(12 downto 0);
            ip_ttl            : in  std_logic_vector(7 downto 0);
            ip_protocol       : in std_logic_vector(7 downto 0);
            ip_src            : in  std_logic_vector(31 downto 0);
            ip_dst            : in  std_logic_vector(31 downto 0);
            alert_bad_version : out std_logic;
            alert_bad_ihl     : out std_logic;
            alert_bad_length  : out std_logic;
            alert_low_ttl     : out std_logic;
            alert_fragment    : out std_logic;
            alert_spoof_src   : out std_logic;
            alert_land_attack : out std_logic;
            alert_any         : out std_logic
        );
    end component;

    -- Helper procedure: send one packet to checker
    procedure send_packet (
        constant ver    : in std_logic_vector(3 downto 0);
        constant ihl    : in std_logic_vector(3 downto 0);
        constant length : in std_logic_vector(15 downto 0);
        constant frag   : in std_logic_vector(12 downto 0):= (others => '0');
        constant ttl    : in std_logic_vector(7 downto 0);
        constant src    : in std_logic_vector(31 downto 0);
        constant dst    : in std_logic_vector(31 downto 0);
        signal ip_version  : out std_logic_vector(3 downto 0);
        signal ip_ihl      : out std_logic_vector(3 downto 0);
        signal ip_length   : out std_logic_vector(15 downto 0);
        signal ip_frag_off : out std_logic_vector(12 downto 0);
        signal ip_ttl      : out std_logic_vector(7 downto 0);
        signal ip_src      : out std_logic_vector(31 downto 0);
        signal ip_dst      : out std_logic_vector(31 downto 0);
        signal parse_done  : out std_logic;
        signal parse_valid : out std_logic;
        constant period    : in time
    ) is
    begin
        -- Set fields
        ip_version  <= ver;
        ip_ihl      <= ihl;
        ip_length   <= length;
        ip_frag_off <= frag;
        ip_ttl      <= ttl;
        ip_src      <= src;
        ip_dst      <= dst;
        parse_valid <= '1';
        wait for period;
        -- Pulse parse_done for 1 cycle
        parse_done <= '1';
        wait for period;
        parse_done <= '0';
        wait for 3 * period;  -- wait to observe alerts
    end procedure;

begin

    clk <= not clk after CLK_PERIOD / 2;

    uut : ipv4_checker
        port map (
            clk               => clk,
            rst               => rst,
            parse_done        => parse_done,
            parse_valid       => parse_valid,
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
        
        process
    begin
        -- Reset
        rst <= '1';
        wait for 5 * CLK_PERIOD;
        rst <= '0';
        wait for 2 * CLK_PERIOD;

        -- Packet 1: Valid packet, no alerts expected
        send_packet(
            ver    => x"4",
            ihl    => x"5",
            length => x"0028",  -- 40 bytes, valid
            frag   => "0000000000000",
            ttl    => x"40",    -- 64, healthy
            src    => x"C0A80101",  -- 192.168.1.1
            dst    => x"C0A80102",  -- 192.168.1.2
            ip_version => ip_version, ip_ihl => ip_ihl,
            ip_length => ip_length, ip_frag_off => ip_frag_off,
            ip_ttl => ip_ttl, ip_src => ip_src, ip_dst => ip_dst,
            parse_done => parse_done, parse_valid => parse_valid,
            period => CLK_PERIOD
        );

        -- Packet 2: Bad IHL = 3
        send_packet(
            ver    => x"4",
            ihl    => x"3",     -- invalid, must be >= 5
            length => x"0028",
            frag   => "0000000000000",
            ttl    => x"40",
            src    => x"C0A80101",
            dst    => x"C0A80102",
            ip_version => ip_version, ip_ihl => ip_ihl,
            ip_length => ip_length, ip_frag_off => ip_frag_off,
            ip_ttl => ip_ttl, ip_src => ip_src, ip_dst => ip_dst,
            parse_done => parse_done, parse_valid => parse_valid,
            period => CLK_PERIOD
        );

        -- Packet 3: Bad length = 10
        send_packet(
            ver    => x"4",
            ihl    => x"5",
            length => x"000A",  -- 10 bytes, impossible
            frag   => "0000000000000",
            ttl    => x"40",
            src    => x"C0A80101",
            dst    => x"C0A80102",
            ip_version => ip_version, ip_ihl => ip_ihl,
            ip_length => ip_length, ip_frag_off => ip_frag_off,
            ip_ttl => ip_ttl, ip_src => ip_src, ip_dst => ip_dst,
            parse_done => parse_done, parse_valid => parse_valid,
            period => CLK_PERIOD
        );

        -- Packet 4: Low TTL = 1
        send_packet(
            ver    => x"4",
            ihl    => x"5",
            length => x"0028",
            frag   => "0000000000000",
            ttl    => x"01",    -- TTL=1, suspicious
            src    => x"C0A80101",
            dst    => x"C0A80102",
            ip_version => ip_version, ip_ihl => ip_ihl,
            ip_length => ip_length, ip_frag_off => ip_frag_off,
            ip_ttl => ip_ttl, ip_src => ip_src, ip_dst => ip_dst,
            parse_done => parse_done, parse_valid => parse_valid,
            period => CLK_PERIOD
        );

        -- Packet 5: Fragment offset = 100
        send_packet(
            ver    => x"4",
            ihl    => x"5",
            length => x"0028",
            frag   => std_logic_vector(to_unsigned(100, 13)),  -- offset=100
            ttl    => x"40",
            src    => x"C0A80101",
            dst    => x"C0A80102",
            ip_version => ip_version, ip_ihl => ip_ihl,
            ip_length => ip_length, ip_frag_off => ip_frag_off,
            ip_ttl => ip_ttl, ip_src => ip_src, ip_dst => ip_dst,
            parse_done => parse_done, parse_valid => parse_valid,
            period => CLK_PERIOD
        );

        -- Packet 6: Land attack - src = dst
        send_packet(
            ver    => x"4",
            ihl    => x"5",
            length => x"0028",
            frag   => "0000000000000",
            ttl    => x"40",
            src    => x"C0A80101",  -- 192.168.1.1
            dst    => x"C0A80101",  -- same as src
            ip_version => ip_version, ip_ihl => ip_ihl,
            ip_length => ip_length, ip_frag_off => ip_frag_off,
            ip_ttl => ip_ttl, ip_src => ip_src, ip_dst => ip_dst,
            parse_done => parse_done, parse_valid => parse_valid,
            period => CLK_PERIOD
        );

        wait;
    end process;

end sim;