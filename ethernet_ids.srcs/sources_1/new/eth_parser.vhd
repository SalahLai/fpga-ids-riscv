library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity eth_parser is
    port (
        clk        : in  std_logic;
        rst        : in  std_logic;
        -- Byte stream in (from rmii_rx)
        rx_byte    : in  std_logic_vector(7 downto 0);
        rx_valid   : in  std_logic;
        rx_sof     : in  std_logic;
        rx_eof     : in  std_logic;
        -- Parsed outputs
        dst_mac    : out std_logic_vector(47 downto 0);
        src_mac    : out std_logic_vector(47 downto 0);
        ethertype  : out std_logic_vector(15 downto 0);
        -- Classification (valid when frame_done pulses)
        is_ipv4    : out std_logic;
        is_arp     : out std_logic;
        is_unknown : out std_logic;
        frame_done : out std_logic
    );
end eth_parser;

architecture rtl of eth_parser is

    type parse_state_t is (
        IDLE,
        ST_DST_MAC,
        ST_SRC_MAC,
        ST_ETHERTYPE,
        PAYLOAD,
        DONE
    );
    signal state    : parse_state_t := IDLE;
    signal byte_idx : unsigned(3 downto 0) := (others => '0');

    signal dst_mac_r  : std_logic_vector(47 downto 0) := (others => '0');
    signal src_mac_r  : std_logic_vector(47 downto 0) := (others => '0');
    signal etype_r    : std_logic_vector(15 downto 0) := (others => '0');

begin

    process(clk)
    begin
        if rising_edge(clk) then

            -- Defaults
            frame_done <= '0';
            is_ipv4    <= '0';
            is_arp     <= '0';
            is_unknown <= '0';

            if rst = '1' then
                state     <= IDLE;
                byte_idx  <= (others => '0');

            else
                case state is

                    when IDLE =>
                        byte_idx <= (others => '0');
                        if rx_sof = '1' then
                            state <= ST_DST_MAC;
                        end if;

                    -- Bytes 0-5: Destination MAC
                    when ST_DST_MAC =>
                        if rx_eof = '1' then
                            state <= IDLE;
                        elsif rx_valid = '1' then
                            dst_mac_r <= dst_mac_r(39 downto 0) & rx_byte;
                            byte_idx  <= byte_idx + 1;
                            if byte_idx = 5 then
                                byte_idx <= (others => '0');
                                state    <= ST_SRC_MAC;
                            end if;
                        end if;

                    -- Bytes 6-11: Source MAC
                    when ST_SRC_MAC =>
                        if rx_eof = '1' then
                            state <= IDLE;
                        elsif rx_valid = '1' then
                            src_mac_r <= src_mac_r(39 downto 0) & rx_byte;
                            byte_idx  <= byte_idx + 1;
                            if byte_idx = 5 then
                                byte_idx <= (others => '0');
                                state    <= ST_ETHERTYPE;
                            end if;
                        end if;

                    -- Bytes 12-13: EtherType
                    when ST_ETHERTYPE =>
                        if rx_eof = '1' then
                            state <= IDLE;
                        elsif rx_valid = '1' then
                            etype_r  <= etype_r(7 downto 0) & rx_byte;
                            byte_idx <= byte_idx + 1;
                            if byte_idx = 1 then
                                byte_idx <= (others => '0');
                                state    <= PAYLOAD;
                            end if;
                        end if;

                    -- Payload: just wait for end of frame
                    when PAYLOAD =>
                        if rx_eof = '1' then
                            state <= DONE;
                        end if;

                    -- Latch and classify
                    when DONE =>
                        dst_mac    <= dst_mac_r;
                        src_mac    <= src_mac_r;
                        ethertype  <= etype_r;
                        frame_done <= '1';

                        if    etype_r = x"0800" then is_ipv4    <= '1';
                        elsif etype_r = x"0806" then is_arp     <= '1';
                        else                          is_unknown <= '1';
                        end if;

                        state <= IDLE;

                    when others =>
                        state <= IDLE;

                end case;
            end if;
        end if;
    end process;

end rtl;