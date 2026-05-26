library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity rmii_rx_tb is
end rmii_rx_tb;

architecture sim of rmii_rx_tb is

    constant CLK_PERIOD : time := 20 ns;  -- 50MHz

    signal clk         : std_logic := '0';
    signal rst         : std_logic := '1';
    signal rmii_crs_dv : std_logic := '0';
    signal rmii_rxd    : std_logic_vector(1 downto 0) := "00";
    signal rx_byte     : std_logic_vector(7 downto 0);
    signal rx_valid    : std_logic;
    signal rx_sof      : std_logic;
    signal rx_eof      : std_logic;

    -- Component declaration
    component rmii_rx
        port (
            clk         : in  std_logic;
            rst         : in  std_logic;
            rmii_crs_dv : in  std_logic;
            rmii_rxd    : in  std_logic_vector(1 downto 0);
            rx_byte     : out std_logic_vector(7 downto 0);
            rx_valid    : out std_logic;
            rx_sof      : out std_logic;
            rx_eof      : out std_logic
        );
    end component;
    
    -- Procedure to send one byte as 4 dibits (LSB first)
    procedure send_byte (
        constant byte : in std_logic_vector(7 downto 0);
        signal   rxd  : out std_logic_vector(1 downto 0);
        signal   crs  : out std_logic;
        constant period : in time
    ) is
    begin
        crs <= '1';
        rxd <= byte(1 downto 0); wait for period;  -- dibit 0 (LSB)
        rxd <= byte(3 downto 2); wait for period;  -- dibit 1
        rxd <= byte(5 downto 4); wait for period;  -- dibit 2
        rxd <= byte(7 downto 6); wait for period;  -- dibit 3 (MSB)
    end procedure;

begin
-- Clock generator
    clk <= not clk after CLK_PERIOD / 2;

    -- Connect UUT
    uut : rmii_rx
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
        
        -- Stimulus
    process
    begin
        -- Release reset
        rst <= '1';
        wait for 5 * CLK_PERIOD;
        rst <= '0';
        wait for 2 * CLK_PERIOD;

        -- === PREAMBLE (10 x 0x55) ===
        -- Real preamble is 7 bytes but we send 10 to be safe
        rmii_crs_dv <= '1';
        for i in 0 to 9 loop
            send_byte(x"55", rmii_rxd, rmii_crs_dv, CLK_PERIOD);
        end loop;

        -- === SFD (0xD5) ===
        send_byte(x"D5", rmii_rxd, rmii_crs_dv, CLK_PERIOD);

        -- === DEST MAC: FF FF FF FF FF FF ===
        for i in 0 to 5 loop
            send_byte(x"FF", rmii_rxd, rmii_crs_dv, CLK_PERIOD);
        end loop;

        -- === SRC MAC: AA BB CC DD EE FF ===
        send_byte(x"AA", rmii_rxd, rmii_crs_dv, CLK_PERIOD);
        send_byte(x"BB", rmii_rxd, rmii_crs_dv, CLK_PERIOD);
        send_byte(x"CC", rmii_rxd, rmii_crs_dv, CLK_PERIOD);
        send_byte(x"DD", rmii_rxd, rmii_crs_dv, CLK_PERIOD);
        send_byte(x"EE", rmii_rxd, rmii_crs_dv, CLK_PERIOD);
        send_byte(x"FF", rmii_rxd, rmii_crs_dv, CLK_PERIOD);

        -- === ETHERTYPE: 08 00 (IPv4) ===
        send_byte(x"08", rmii_rxd, rmii_crs_dv, CLK_PERIOD);
        send_byte(x"00", rmii_rxd, rmii_crs_dv, CLK_PERIOD);

        -- === PAYLOAD: DE AD BE EF ===
        send_byte(x"DE", rmii_rxd, rmii_crs_dv, CLK_PERIOD);
        send_byte(x"AD", rmii_rxd, rmii_crs_dv, CLK_PERIOD);
        send_byte(x"BE", rmii_rxd, rmii_crs_dv, CLK_PERIOD);
        send_byte(x"EF", rmii_rxd, rmii_crs_dv, CLK_PERIOD);

        -- === END OF FRAME ===
        rmii_crs_dv <= '0';
        rmii_rxd    <= "00";
        wait for 10 * CLK_PERIOD;

        -- Done
        wait;
    end process;

end sim;