library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity ipv4_checker is
    port (
        clk         : in std_logic;
        rst         : in std_logic;
        -- Fields from ipv4_parser (sample when parse_done='1')
        parse_done  : in std_logic;
        parse_valid : in std_logic;
        ip_version  : in std_logic_vector(3 downto 0);
        ip_ihl      : in std_logic_vector(3 downto 0);
        ip_length   : in std_logic_vector(15 downto 0);
        ip_flags    : in std_logic_vector(2 downto 0);
        ip_frag_off : in std_logic_vector(12 downto 0);
        ip_ttl      : in std_logic_vector(7 downto 0);
        ip_protocol : in std_logic_vector(7 downto 0);
        ip_src      : in std_logic_vector(31 downto 0);
        ip_dst      : in std_logic_vector(31 downto 0);
        
        -- Alert outputs (pulse 1 cycle when triggered)
        alert_bad_version  : out std_logic;
        alert_bad_ihl      : out std_logic;
        alert_bad_length   : out std_logic;
        alert_low_ttl      : out std_logic;
        alert_fragment     : out std_logic;
        alert_spoof_src    : out std_logic;
        alert_land_attack  : out std_logic;
        
        -- R8-R12 new alerts
        alert_bogon_loop : out std_logic;
        alert_bogon_link : out std_logic;
        alert_bogon_mcast : out std_logic;
        alert_ip_options : out std_logic;
        alert_reserved_bit : out std_logic;
        -- Enable flags (from rule BRAM, default all 1)
        bogon_check_en : in std_logic;
        ip_options_en : in std_logic;
        reserved_bit_en : in std_logic;
        -- Summary
        alert_any   : out std_logic
        
        );
end ipv4_checker;

architecture rtl of ipv4_checker is
begin

    process(clk)
        variable any_alert : std_logic;
    begin
        if rising_edge(clk) then

            -- Defaults
            alert_bad_version <= '0';
            alert_bad_ihl      <= '0';
            alert_bad_length   <= '0';
            alert_low_ttl      <= '0';
            alert_fragment     <= '0';
            alert_spoof_src    <= '0';
            alert_land_attack  <= '0';
            alert_any          <= '0';
            alert_bogon_loop   <= '0';
            alert_bogon_link   <= '0';
            alert_bogon_mcast  <= '0';
            alert_ip_options   <= '0';
            alert_reserved_bit <= '0';
            
            if rst = '1' then
                null;

            elsif parse_done = '1' then

                any_alert := '0';

                -- R1: Version must be 4
                if ip_version /= x"4" then
                    alert_bad_version <= '1';
                    any_alert := '1';
                end if;

                -- R2: IHL must be >= 5
                if unsigned(ip_ihl) < 5 then
                    alert_bad_ihl <= '1';
                    any_alert := '1';
                end if;

                -- R3: Total length must be >= 20
                if unsigned(ip_length) < 20 then
                    alert_bad_length <= '1';
                    any_alert := '1';
                end if;

                -- R4: TTL must be > 1
                if unsigned(ip_ttl) <= 1 then
                    alert_low_ttl <= '1';
                    any_alert := '1';
                end if;

                -- R5: Fragment offset must be 0
                if unsigned(ip_frag_off) > 0 then
                    alert_fragment <= '1';
                    any_alert := '1';
                end if;

                -- R6: Source IP must not be 0.0.0.0
                if ip_src = x"00000000" then
                    alert_spoof_src <= '1';
                    any_alert := '1';
                end if;

                -- R7: Source IP must not equal Dest IP (Land attack)
                if ip_src = ip_dst then
                    alert_land_attack <= '1';
                    any_alert := '1';
                end if;
                -- R8: Bogon source - loopback (127.0.0.0/8)
                if bogon_check_en = '1' and ip_src(31 downto 24) = x"7F" then 
                alert_bogon_loop <='1';
                any_alert := '1';
                end if;
                
                -- R9: Bogon source - link-local (169.254.0.0/16)
                if bogon_check_en = '1' and ip_src(31 downto 16) = x"A9FE" then 
                alert_bogon_link <='1';
                any_alert := '1';
                end if;
                
                -- R10: Bogon source - multicast as source (224.0.0.0/4)
                if bogon_check_en = '1' and ip_src(31 downto 28) = x"E" then 
                alert_bogon_mcast <='1';
                any_alert := '1';
                end if;
                -- R11: IP options present (IHL > 5)
                if ip_options_en = '1' and unsigned(ip_ihl) > 5 then 
                alert_ip_options <='1';
                any_alert := '1';
                end if;
                -- R12: Reserved IPv4 flag bit set (bit 2 of flags)
                if reserved_bit_en = '1' and ip_flags(2) = '1' then 
                alert_reserved_bit <='1';
                any_alert := '1';
                end if;
                
                
                
                alert_any <= any_alert;

            end if;
        end if;
    end process;

end rtl;