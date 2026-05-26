library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity tcp_parser is
    port (
        clk         : in std_logic;
        rst         : in std_logic;
        -- Byte stream (same as all other parsers)
        rx_byte     : in std_logic_vector(7 downto 0);
        rx_valid    : in std_logic;
        rx_sof      : in std_logic;
        rx_eof      : in std_logic;
        -- From ipv4_parser (needed to locate TCP start)
        ip_protocol : in std_logic_vector(7 downto 0);
        ip_ihl      : in std_logic_vector(3 downto 0);
        ip_valid    : in std_logic;  -- pulses when ipv4_parser has fresh data
        -- Extracted TCP fields (valid when parse_done pulses)
        tcp_src_port : out std_logic_vector(15 downto 0);
        tcp_dst_port : out std_logic_vector(15 downto 0);
        tcp_flags    : out std_logic_vector(7 downto 0);
        tcp_seq      : out std_logic_vector(31 downto 0);
        -- Control
        parse_done  : out std_logic;
        parse_valid : out std_logic   -- '0' if not TCP
    );
end tcp_parser;

architecture rtl of tcp_parser is

    type tcp_state_t is (
        ST_IDLE,
        ST_SKIP,      -- skip Ethernet + IPv4 header bytes
        ST_TCP_HEADER, -- parse TCP fields
        ST_WAIT_EOF,
        ST_DONE
    );
    signal state : tcp_state_t := ST_IDLE;

    -- Counts bytes in current frame
    signal byte_cnt  : unsigned(7 downto 0) := (others => '0');

    -- Where TCP header starts (calculated from IHL)
    -- tcp_start = 14 + IHL*4
    signal tcp_start : unsigned(7 downto 0) := (others => '0');

    -- Is this frame TCP?
    signal is_tcp    : std_logic := '0';

    -- Internal registers
    signal src_port_r : std_logic_vector(15 downto 0) := (others => '0');
    signal dst_port_r : std_logic_vector(15 downto 0) := (others => '0');
    signal flags_r    : std_logic_vector(7 downto 0)  := (others => '0');
    signal seq_r      : std_logic_vector(31 downto 0) := (others => '0');

begin
process(clk)
    begin
        if rising_edge(clk) then

            parse_done  <= '0';
            parse_valid <= '0';

            if rst = '1' then
                state     <= ST_IDLE;
                byte_cnt  <= (others => '0');
                is_tcp    <= '0';

            else
                -- Capture ip_protocol and ip_ihl when ipv4_parser signals valid
                -- This happens BEFORE rx_sof of the same frame's TCP section
                if ip_valid = '1' then
                    if ip_protocol = x"06" then
                        is_tcp <= '1';
                    else
                        is_tcp <= '0';
                    end if;
                    -- tcp_start = 14 + IHL*4
                    tcp_start <= to_unsigned(14, 8) +
                                 shift_left(resize(unsigned(ip_ihl), 8), 2);
                end if;

                case state is

                    when ST_IDLE =>
                        byte_cnt <= (others => '0');
                        if rx_sof = '1' then
                            state <= ST_SKIP;
                        end if;

                    -- Skip bytes until we reach tcp_start
                    when ST_SKIP =>
                        if rx_eof = '1' then
                            state <= ST_IDLE;
                        elsif rx_valid = '1' then
                            byte_cnt <= byte_cnt + 1;
                            if byte_cnt = tcp_start - 1 then
                                byte_cnt <= (others => '0');
                                if is_tcp = '1' then
                                    state <= ST_TCP_HEADER;
                                else
                                    state <= ST_WAIT_EOF;
                                end if;
                            end if;
                        end if;

                    -- Parse TCP header fields
                    when ST_TCP_HEADER =>
                        if rx_eof = '1' then
                            state <= ST_IDLE;
                        elsif rx_valid = '1' then
                            byte_cnt <= byte_cnt + 1;

                            case to_integer(byte_cnt) is
                                when 0 => src_port_r(15 downto 8) <= rx_byte;
                                when 1 => src_port_r(7 downto 0)  <= rx_byte;
                                when 2 => dst_port_r(15 downto 8) <= rx_byte;
                                when 3 => dst_port_r(7 downto 0)  <= rx_byte;
                                when 4 => seq_r(31 downto 24) <= rx_byte;
                                when 5 => seq_r(23 downto 16) <= rx_byte;
                                when 6 => seq_r(15 downto 8)  <= rx_byte;
                                when 7 => seq_r(7 downto 0)   <= rx_byte;
                                -- bytes 8-11: ack number (skip)
                                -- byte 12: data offset (skip)
                                when 13 => flags_r <= rx_byte;  -- flags byte
                                when 19 =>
                                    -- Reached end of standard TCP header
                                    state <= ST_WAIT_EOF;
                                when others => null;
                            end case;
                        end if;

                    when ST_WAIT_EOF =>
                        if rx_eof = '1' then
                            state <= ST_DONE;
                        end if;

                    when ST_DONE =>
                        tcp_src_port <= src_port_r;
                        tcp_dst_port <= dst_port_r;
                        tcp_flags    <= flags_r;
                        tcp_seq      <= seq_r;
                        parse_done   <= '1';
                        if is_tcp = '1' then
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