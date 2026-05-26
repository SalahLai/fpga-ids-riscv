library ieee;
use ieee.std_logic_1164.all;

entity clk_divider_tb is
end clk_divider_tb;

architecture sim of clk_divider_tb is

    constant CLK_FREQ    : integer := 10;
    constant CLK_PERIOD  : time    := 20 ns;

    signal clk  : std_logic := '0';
    signal rst  : std_logic := '1';
    signal tick : std_logic;

    component clk_divider
        generic (CLK_FREQ_HZ : integer);
        port (
            clk  : in  std_logic;
            rst  : in  std_logic;
            tick : out std_logic
        );
    end component;

begin

    uut : clk_divider
        generic map (CLK_FREQ_HZ => CLK_FREQ)
        port map (
            clk  => clk,
            rst  => rst,
            tick => tick
        );

    -- Clock generator
    clk <= not clk after CLK_PERIOD / 2;

    -- Stimulus
    process
    begin
        rst <= '1';
        wait for 5 * CLK_PERIOD;
        rst <= '0';
        wait for 35 * CLK_PERIOD;
        wait;
    end process;

end sim;