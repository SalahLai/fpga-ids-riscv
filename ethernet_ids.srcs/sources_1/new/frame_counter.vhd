library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity frame_counter is
    generic (
        CLK_FREQ_HZ : integer := 50_000_000
    );
    port (
        clk        : in  std_logic;
        rst        : in  std_logic;
        frame_done : in  std_logic;
        is_ipv4    : in  std_logic;
        is_arp     : in  std_logic;
        is_unknown : in  std_logic;
        -- Counts (updated every second)
        fps_total   : out unsigned(15 downto 0);
        fps_ipv4    : out unsigned(15 downto 0);
        fps_arp     : out unsigned(15 downto 0);
        fps_unknown : out unsigned(15 downto 0);
        led_active  : out std_logic
    );
end frame_counter;

architecture rtl of frame_counter is

    signal tick_counter : unsigned(25 downto 0) := (others => '0');
    signal one_sec_tick : std_logic := '0';

    signal acc_total   : unsigned(15 downto 0) := (others => '0');
    signal acc_ipv4    : unsigned(15 downto 0) := (others => '0');
    signal acc_arp     : unsigned(15 downto 0) := (others => '0');
    signal acc_unknown : unsigned(15 downto 0) := (others => '0');

    signal blink_ctr   : unsigned(22 downto 0) := (others => '0');
    signal total_reg   : unsigned(15 downto 0) := (others => '0');

begin

    -- 1Hz tick
    process(clk)
    begin
        if rising_edge(clk) then
            one_sec_tick <= '0';
            if tick_counter = CLK_FREQ_HZ - 1 then
                tick_counter <= (others => '0');
                one_sec_tick <= '1';
            else
                tick_counter <= tick_counter + 1;
            end if;
        end if;
    end process;

    -- Accumulators
    process(clk)
    begin
        if rising_edge(clk) then
            if rst = '1' then
                acc_total   <= (others => '0');
                acc_ipv4    <= (others => '0');
                acc_arp     <= (others => '0');
                acc_unknown <= (others => '0');
            elsif one_sec_tick = '1' then
                -- Latch counts and reset accumulators
                fps_total   <= acc_total;
                fps_ipv4    <= acc_ipv4;
                fps_arp     <= acc_arp;
                fps_unknown <= acc_unknown;
                total_reg   <= acc_total;
                acc_total   <= (others => '0');
                acc_ipv4    <= (others => '0');
                acc_arp     <= (others => '0');
                acc_unknown <= (others => '0');
            elsif frame_done = '1' then
                acc_total <= acc_total + 1;
                if    is_ipv4    = '1' then acc_ipv4    <= acc_ipv4    + 1;
                elsif is_arp     = '1' then acc_arp     <= acc_arp     + 1;
                elsif is_unknown = '1' then acc_unknown <= acc_unknown + 1;
                end if;
            end if;
        end if;
    end process;

    -- LED blinks when traffic present
    process(clk)
    begin
        if rising_edge(clk) then
            blink_ctr <= blink_ctr + 1;
            if total_reg > 0 then
                led_active <= blink_ctr(22);
            else
                led_active <= '0';
            end if;
        end if;
    end process;

end rtl;