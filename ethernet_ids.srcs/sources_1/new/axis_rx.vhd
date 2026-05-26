library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity axis_rx is
    port (
        clk           : in  std_logic;
        rst           : in  std_logic;
        -- AXI-Stream slave (from DMA)
        s_axis_tdata  : in  std_logic_vector(7 downto 0);
        s_axis_tvalid : in  std_logic;
        s_axis_tlast  : in  std_logic;
        s_axis_tready : out std_logic;
        -- Byte stream to IDS pipeline (same interface as rmii_rx)
        rx_byte       : out std_logic_vector(7 downto 0);
        rx_valid      : out std_logic;
        rx_sof        : out std_logic;
        rx_eof        : out std_logic
    );
end axis_rx;

architecture rtl of axis_rx is
    signal first_byte : std_logic := '1';
begin
    -- Always ready: we never back-pressure the DMA
    s_axis_tready <= '1';

    process(clk)
    begin
        if rising_edge(clk) then
            rx_valid <= '0';
            rx_sof   <= '0';
            rx_eof   <= '0';

            if rst = '1' then
                first_byte <= '1';
            elsif s_axis_tvalid = '1' then
                rx_byte  <= s_axis_tdata;
                rx_valid <= '1';

                if first_byte = '1' then
                    rx_sof     <= '1';
                    first_byte <= '0';
                end if;

                if s_axis_tlast = '1' then
                    rx_eof     <= '1';
                    first_byte <= '1';  -- next valid byte starts a new frame
                end if;
            end if;
        end if;
    end process;
end rtl;