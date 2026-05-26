library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity ipv4_parser is
    port (
        clk      : in std_logic;
        rst      : in std_logic;
        -- Byte stream (same stream as eth_parser)
        rx_byte  : in std_logic_vector(7 downto 0);
        rx_valid : in std_logic;
        rx_sof   : in std_logic;
        rx_eof   : in std_logic;
        -- Extracted fields (valid when parse_done pulses)
        ip_version   : out std_logic_vector(3 downto 0);
        ip_ihl       : out std_logic_vector(3 downto 0);
        ip_length    : out std_logic_vector(15 downto 0);
        ip_flags     : out std_logic_vector(2 downto 0);
        ip_frag_off  : out std_logic_vector(12 downto 0);
        ip_ttl       : out std_logic_vector(7 downto 0);
        ip_protocol  : out std_logic_vector(7 downto 0);
        ip_src       : out std_logic_vector(31 downto 0);
        ip_dst       : out std_logic_vector(31 downto 0);
        -- Control
        parse_done   : out std_logic;
        parse_valid  : out std_logic  -- '0' if not IPv4
    );
end ipv4_parser;

architecture rtl of ipv4_parser is

    type ip_state_t is (
        ST_IDLE,
        ST_ETH_HEADER,   -- skip bytes 0-13 (Ethernet header)
        ST_IP_HEADER,    -- parse bytes 14+ (IPv4 header)
        ST_WAIT_EOF,     -- wait for frame end
        ST_DONE          -- output results
    );
    signal state : ip_state_t := ST_IDLE;

    -- Byte counter tracks absolute position in frame
    signal byte_cnt : unsigned(7 downto 0) := (others => '0');

    -- Header end position = 14 + IHL*4
    signal header_end : unsigned(7 downto 0) := (others => '0');

    -- Internal field registers
    signal version_r  : std_logic_vector(3 downto 0) := (others => '0');
    signal ihl_r      : std_logic_vector(3 downto 0) := (others => '0');
    signal length_r   : std_logic_vector(15 downto 0) := (others => '0');
    signal flags_r    : std_logic_vector(2 downto 0) := (others => '0');
    signal frag_off_r : std_logic_vector(12 downto 0) := (others => '0');
    signal ttl_r      : std_logic_vector(7 downto 0) := (others => '0');
    signal protocol_r : std_logic_vector(7 downto 0) := (others => '0');
    signal src_r      : std_logic_vector(31 downto 0) := (others => '0');
    signal dst_r      : std_logic_vector(31 downto 0) := (others => '0');

begin
process(clk)
    begin
        if rising_edge(clk) then

            -- Defaults
            parse_done  <= '0';
            parse_valid <= '0';

            if rst = '1' then
                state    <= ST_IDLE;
                byte_cnt <= (others => '0');

            else
                case state is

                    when ST_IDLE =>
                        byte_cnt <= (others => '0');
                        if rx_sof = '1' then
                            state <= ST_ETH_HEADER;
                        end if;

                    -- Skip 14 bytes of Ethernet header
                    when ST_ETH_HEADER =>
                        if rx_eof = '1' then
                            state <= ST_IDLE;
                        elsif rx_valid = '1' then
                            byte_cnt <= byte_cnt + 1;
                            if byte_cnt = 13 then
                                -- Next byte is byte 14 = first IP byte
                                byte_cnt <= (others => '0');
                                state    <= ST_IP_HEADER;
                            end if;
                        end if;

                    -- Parse IPv4 header fields
                    when ST_IP_HEADER =>
                        if rx_eof = '1' then
                            state <= ST_IDLE;
                        elsif rx_valid = '1' then
                            byte_cnt <= byte_cnt + 1;

                            case to_integer(byte_cnt) is

                                when 0 =>  -- Byte 14: Version + IHL
                                    version_r  <= rx_byte(7 downto 4);
                                    ihl_r      <= rx_byte(3 downto 0);
                                    -- Calculate where header ends
                                    -- header_end = IHL*4 (relative to IP start)
                                    header_end <= shift_left(
                                        resize(unsigned(rx_byte(3 downto 0)), 8), 2
                                    );

                                when 2 =>  -- Byte 16: Total Length high
                                    length_r(15 downto 8) <= rx_byte;

                                when 3 =>  -- Byte 17: Total Length low
                                    length_r(7 downto 0) <= rx_byte;

                                when 6 =>  -- Byte 20: Flags + Frag Offset high
                                    flags_r    <= rx_byte(7 downto 5);
                                    frag_off_r(12 downto 8) <= rx_byte(4 downto 0);

                                when 7 =>  -- Byte 21: Frag Offset low
                                    frag_off_r(7 downto 0) <= rx_byte;

                                when 8 =>  -- Byte 22: TTL
                                    ttl_r <= rx_byte;

                                when 9 =>  -- Byte 23: Protocol
                                    protocol_r <= rx_byte;

                                when 12 =>  -- Byte 26: Src IP byte 0
                                    src_r(31 downto 24) <= rx_byte;

                                when 13 =>  -- Byte 27: Src IP byte 1
                                    src_r(23 downto 16) <= rx_byte;

                                when 14 =>  -- Byte 28: Src IP byte 2
                                    src_r(15 downto 8) <= rx_byte;

                                when 15 =>  -- Byte 29: Src IP byte 3
                                    src_r(7 downto 0) <= rx_byte;

                                when 16 =>  -- Byte 30: Dst IP byte 0
                                    dst_r(31 downto 24) <= rx_byte;

                                when 17 =>  -- Byte 31: Dst IP byte 1
                                    dst_r(23 downto 16) <= rx_byte;

                                when 18 =>  -- Byte 32: Dst IP byte 2
                                    dst_r(15 downto 8) <= rx_byte;

                                when 19 =>  -- Byte 33: Dst IP byte 3
                                    dst_r(7 downto 0) <= rx_byte;

                                when others => null;

                            end case;

                            -- Check if we've reached end of IP header
                            if byte_cnt = header_end - 1 then
                                state <= ST_WAIT_EOF;
                            end if;
                        end if;

                    -- Wait for frame to finish
                    when ST_WAIT_EOF =>
                        if rx_eof = '1' then
                            state <= ST_DONE;
                        end if;

                    -- Latch outputs
                    when ST_DONE =>
                        ip_version  <= version_r;
                        ip_ihl      <= ihl_r;
                        ip_length   <= length_r;
                        ip_flags    <= flags_r;
                        ip_frag_off <= frag_off_r;
                        ip_ttl      <= ttl_r;
                        ip_protocol <= protocol_r;
                        ip_src      <= src_r;
                        ip_dst      <= dst_r;
                        parse_done  <= '1';

                        -- Only valid if version = 4
                        if version_r = x"4" then
                            parse_valid <= '1';
                        end if;

                        state <= ST_IDLE;

                    when others =>
                        state <= ST_IDLE;

                end case;
            end if;
        end if;
    end process;

end rtl;
