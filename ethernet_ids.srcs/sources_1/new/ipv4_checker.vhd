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
            alert_bad_ihl     <= '0';
            alert_bad_length  <= '0';
            alert_low_ttl     <= '0';
            alert_fragment    <= '0';
            alert_spoof_src   <= '0';
            alert_land_attack <= '0';
            alert_any         <= '0';

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

                alert_any <= any_alert;

            end if;
        end if;
    end process;

end rtl;