library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity rmii_rx is
    port (
        clk         : in  std_logic;
        rst         : in  std_logic;
        -- RMII PHY signals
        rmii_crs_dv : in  std_logic;
        rmii_rxd    : in  std_logic_vector(1 downto 0);
        -- Output byte stream
        rx_byte     : out std_logic_vector(7 downto 0);
        rx_valid    : out std_logic;
        rx_sof      : out std_logic;
        rx_eof      : out std_logic
    );
end rmii_rx;


architecture rtl of rmii_rx is

    -- FSM states
    type rx_state_t is (IDLE, PREAMBLE, DATA);
    signal state : rx_state_t := IDLE;

    -- Dibit counter: counts 0..3 (4 dibits = 1 byte)
    signal dibit_cnt : unsigned(1 downto 0) := (others => '0');

    -- Shift register: assembles dibits into bytes
    signal shift_reg : std_logic_vector(7 downto 0) := (others => '0');

    -- Preamble dibit counter
    signal pre_cnt : unsigned(4 downto 0) := (others => '0');

begin
process(clk)
    begin
        if rising_edge(clk) then

            -- Default outputs every cycle
            rx_valid <= '0';
            rx_sof   <= '0';
            rx_eof   <= '0';

            if rst = '1' then
                state     <= IDLE;
                dibit_cnt <= (others => '0');
                pre_cnt   <= (others => '0');
                shift_reg <= (others => '0');

            else
                case state is

                    -- Wait for carrier
                    when IDLE =>
                        dibit_cnt <= (others => '0');
                        pre_cnt   <= (others => '0');
                        if rmii_crs_dv = '1' then
                            state <= PREAMBLE;
                        end if;

                    -- Consume preamble + detect SFD
                    when PREAMBLE =>
                        if rmii_crs_dv = '0' then
                            -- Lost signal before SFD, abort
                            state <= IDLE;
                        elsif rmii_rxd = "01" then
                            -- Still in preamble
                            pre_cnt <= pre_cnt + 1;
                        elsif rmii_rxd = "11" and pre_cnt >= 8 then
                            -- SFD detected, data starts next cycle
                            dibit_cnt <= (others => '0');
                            shift_reg <= (others => '0');
                            rx_sof    <= '1';
                            state     <= DATA;
                        else
                            -- Unexpected dibit, reset
                            state <= IDLE;
                        end if;

                    -- Receive data bytes
                    when DATA =>
                        if rmii_crs_dv = '0' and rmii_rxd = "00" then
                            -- Clean end of frame
                            rx_eof <= '1';
                            state  <= IDLE;
                        else
                            -- Shift dibit in from the top (LSB first)
                            shift_reg <= rmii_rxd & shift_reg(7 downto 2);
                            dibit_cnt <= dibit_cnt + 1;

                            if dibit_cnt = "11" then
                                -- 4 dibits received = full byte ready
                                rx_byte  <= rmii_rxd & shift_reg(7 downto 2);
                                rx_valid <= '1';
                            end if;
                        end if;

                    when others =>
                        state <= IDLE;

                end case;
            end if;
        end if;
    end process;

end rtl;