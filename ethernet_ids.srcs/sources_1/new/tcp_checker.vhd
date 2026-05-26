library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity tcp_checker is
    port (
        clk          : in std_logic;
        rst          : in std_logic;
        -- From tcp_parser
        parse_done   : in std_logic;
        parse_valid  : in std_logic;
        tcp_src_port : in std_logic_vector(15 downto 0);
        tcp_dst_port : in std_logic_vector(15 downto 0);
        tcp_flags    : in std_logic_vector(7 downto 0);
        -- Alerts
        alert_syn_fin      : out std_logic;  -- T1: SYN+FIN together
        alert_syn_rst      : out std_logic;  -- T2: SYN+RST together
        alert_null_scan    : out std_logic;  -- T3: no flags set
        alert_xmas_scan    : out std_logic;  -- T4: all flags set
        alert_forbidden    : out std_logic;  -- T5: forbidden dst port
        alert_any          : out std_logic
    );
end tcp_checker;

architecture rtl of tcp_checker is

    -- Flag bit positions
    alias flag_fin : std_logic is tcp_flags(0);
    alias flag_syn : std_logic is tcp_flags(1);
    alias flag_rst : std_logic is tcp_flags(2);
    alias flag_urg : std_logic is tcp_flags(5);

begin

    process(clk)
        variable any_alert : std_logic;
        variable dst_port_int : integer range 0 to 65535;
    begin
        if rising_edge(clk) then

            alert_syn_fin   <= '0';
            alert_syn_rst   <= '0';
            alert_null_scan <= '0';
            alert_xmas_scan <= '0';
            alert_forbidden <= '0';
            alert_any       <= '0';

            if rst = '1' then
                null;

            elsif parse_done = '1' and parse_valid = '1' then

                any_alert     := '0';
                dst_port_int  := to_integer(unsigned(tcp_dst_port));

                -- T1: SYN + FIN simultaneously
                if flag_syn = '1' and flag_fin = '1' then
                    alert_syn_fin <= '1';
                    any_alert     := '1';
                end if;

                -- T2: SYN + RST simultaneously
                if flag_syn = '1' and flag_rst = '1' then
                    alert_syn_rst <= '1';
                    any_alert     := '1';
                end if;

                -- T3: NULL scan - no flags set at all
                if tcp_flags = x"00" then
                    alert_null_scan <= '1';
                    any_alert       := '1';
                end if;

                -- T4: XMAS scan - all flags set
                if tcp_flags = x"FF" then
                    alert_xmas_scan <= '1';
                    any_alert       := '1';
                end if;

                -- T5: Forbidden destination ports
                if dst_port_int = 23 or   -- Telnet
                   dst_port_int = 21 or   -- FTP
                   dst_port_int = 69 then  -- TFTP
                    alert_forbidden <= '1';
                    any_alert       := '1';
                end if;

                alert_any <= any_alert;

            end if;
        end if;
    end process;

end rtl;