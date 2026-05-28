library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity udp_checker is
    port (
        clk          : in  std_logic;
        rst          : in  std_logic;
        parse_done   : in  std_logic;
        parse_valid  : in  std_logic;
        udp_src_port : in  std_logic_vector(15 downto 0);
        udp_dst_port : in  std_logic_vector(15 downto 0);
        udp_length   : in  std_logic_vector(15 downto 0);
        ip_src       : in  std_logic_vector(31 downto 0);
        ip_dst       : in  std_logic_vector(31 downto 0);
        -- Forbidden dst port table (0 = disabled)
        forbidden_port_0 : in std_logic_vector(15 downto 0);
        forbidden_port_1 : in std_logic_vector(15 downto 0);
        forbidden_port_2 : in std_logic_vector(15 downto 0);
        forbidden_port_3 : in std_logic_vector(15 downto 0);
        forbidden_port_4 : in std_logic_vector(15 downto 0);
        forbidden_port_5 : in std_logic_vector(15 downto 0);
        forbidden_port_6 : in std_logic_vector(15 downto 0);
        forbidden_port_7 : in std_logic_vector(15 downto 0);
        -- Alert outputs
        alert_udp_forbidden   : out std_logic;  -- U1: forbidden dst port
        alert_udp_short       : out std_logic;  -- U2: length < 8
        alert_udp_zero_len    : out std_logic;  -- U3: length = 0
        alert_udp_amplify     : out std_logic;  -- U4: amplification src port
        alert_udp_land        : out std_logic;  -- U5: src=dst ip+port
        alert_udp_oversized   : out std_logic;  -- U6: length > 1472
        alert_udp_port_zero   : out std_logic;  -- U7: port 0 used
        alert_udp_ssdp        : out std_logic;  -- U8: SSDP abuse (port 1900)
        alert_udp_memcached   : out std_logic;  -- U9: Memcached (port 11211)
        alert_any             : out std_logic
    );
end udp_checker;

architecture rtl of udp_checker is
    -- Amplification source ports (known reflection/amplification services)
    constant AMP_DNS      : std_logic_vector(15 downto 0) := x"0035";  -- 53
    constant AMP_NTP      : std_logic_vector(15 downto 0) := x"007B";  -- 123
    constant AMP_SSDP     : std_logic_vector(15 downto 0) := x"076C";  -- 1900
    constant AMP_MEMCACHE : std_logic_vector(15 downto 0) := x"2BCB";  -- 11211
    constant AMP_CHARGEN  : std_logic_vector(15 downto 0) := x"0013";  -- 19
    constant MAX_UDP_LEN  : unsigned(15 downto 0) := to_unsigned(1472, 16);
begin
    process(clk)
        variable any_alert : std_logic;
    begin
        if rising_edge(clk) then

            alert_udp_forbidden <= '0';
            alert_udp_short     <= '0';
            alert_udp_zero_len  <= '0';
            alert_udp_amplify   <= '0';
            alert_udp_land      <= '0';
            alert_udp_oversized <= '0';
            alert_udp_port_zero <= '0';
            alert_udp_ssdp      <= '0';
            alert_udp_memcached <= '0';
            alert_any           <= '0';

            if rst = '1' then
                null;

            elsif parse_done = '1' and parse_valid = '1' then

                any_alert := '0';

                -- U1: Forbidden destination port (configurable table)
                if (forbidden_port_0 /= x"0000" and udp_dst_port = forbidden_port_0) or
                   (forbidden_port_1 /= x"0000" and udp_dst_port = forbidden_port_1) or
                   (forbidden_port_2 /= x"0000" and udp_dst_port = forbidden_port_2) or
                   (forbidden_port_3 /= x"0000" and udp_dst_port = forbidden_port_3) or
                   (forbidden_port_4 /= x"0000" and udp_dst_port = forbidden_port_4) or
                   (forbidden_port_5 /= x"0000" and udp_dst_port = forbidden_port_5) or
                   (forbidden_port_6 /= x"0000" and udp_dst_port = forbidden_port_6) or
                   (forbidden_port_7 /= x"0000" and udp_dst_port = forbidden_port_7) then
                    alert_udp_forbidden <= '1'; any_alert := '1';
                end if;

                -- U2: Length field < 8 (impossible - header alone is 8 bytes)
                if unsigned(udp_length) < 8 then
                    alert_udp_short <= '1'; any_alert := '1';
                end if;

                -- U3: Length = 0 (completely invalid)
                if udp_length = x"0000" then
                    alert_udp_zero_len <= '1'; any_alert := '1';
                end if;

                -- U4: Amplification attack response
                -- Packet arriving FROM a known amplification service port
                -- means we are the target of an amplification DDoS
                if udp_src_port = AMP_DNS      or
                   udp_src_port = AMP_NTP      or
                   udp_src_port = AMP_MEMCACHE or
                   udp_src_port = AMP_CHARGEN  then
                    alert_udp_amplify <= '1'; any_alert := '1';
                end if;

                -- U5: UDP Land attack (src ip+port = dst ip+port)
                if ip_src = ip_dst and
                   udp_src_port = udp_dst_port then
                    alert_udp_land <= '1'; any_alert := '1';
                end if;

                -- U6: Oversized UDP (length > MTU payload limit)
                -- 1472 = 1500 (Ethernet MTU) - 20 (IP) - 8 (UDP)
                if unsigned(udp_length) > MAX_UDP_LEN then
                    alert_udp_oversized <= '1'; any_alert := '1';
                end if;

                -- U7: Reserved port zero used (src or dst)
                if udp_src_port = x"0000" or
                   udp_dst_port = x"0000" then
                    alert_udp_port_zero <= '1'; any_alert := '1';
                end if;

                -- U8: SSDP/UPnP abuse (port 1900)
                -- Used in massive amplification attacks against IoT devices
                if udp_dst_port = AMP_SSDP then
                    alert_udp_ssdp <= '1'; any_alert := '1';
                end if;

                -- U9: Memcached amplification (port 11211)
                -- Amplification factor up to 51,000x - most powerful known UDP DDoS
                if udp_dst_port = AMP_MEMCACHE or
                   udp_src_port = AMP_MEMCACHE then
                    alert_udp_memcached <= '1'; any_alert := '1';
                end if;

                alert_any <= any_alert;

            end if;
        end if;
    end process;

end rtl;