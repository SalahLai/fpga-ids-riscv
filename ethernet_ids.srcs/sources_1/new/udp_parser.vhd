library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity udp_parser is
    port (
        clk         : in  std_logic;
        rst         : in  std_logic;
        rx_byte     : in  std_logic_vector(7 downto 0);
        rx_valid    : in  std_logic;
        rx_sof      : in  std_logic;
        rx_eof      : in  std_logic;
        ip_protocol : in  std_logic_vector(7 downto 0);
        ip_ihl      : in  std_logic_vector(3 downto 0);
        ip_valid    : in  std_logic;
        udp_src_port : out std_logic_vector(15 downto 0);
        udp_dst_port : out std_logic_vector(15 downto 0);
        udp_length   : out std_logic_vector(15 downto 0);
        parse_done   : out std_logic;
        parse_valid  : out std_logic
    );
end udp_parser;

architecture rtl of udp_parser is

    type udp_state_t is (ST_IDLE, ST_SKIP, ST_UDP_HEADER, ST_WAIT_EOF, ST_DONE);
    signal state     : udp_state_t := ST_IDLE;
    signal byte_cnt  : unsigned(7 downto 0) := (others => '0');
    signal udp_start : unsigned(7 downto 0) := (others => '0');
    signal is_udp    : std_logic := '0';

    signal src_port_r : std_logic_vector(15 downto 0) := (others => '0');
    signal dst_port_r : std_logic_vector(15 downto 0) := (others => '0');
    signal length_r   : std_logic_vector(15 downto 0) := (others => '0');

begin
    process(clk)
    begin
        if rising_edge(clk) then
            parse_done  <= '0';
            parse_valid <= '0';

            -- Capture protocol and IHL when IPv4 parser signals valid
            if ip_valid = '1' then
                if ip_protocol = x"11" then
                    is_udp <= '1';
                else
                    is_udp <= '0';
                end if;
                udp_start <= to_unsigned(14, 8) +
                             shift_left(resize(unsigned(ip_ihl), 8), 2);
            end if;

            if rst = '1' then
                state    <= ST_IDLE;
                byte_cnt <= (others => '0');
                is_udp   <= '0';
            else
                case state is

                    when ST_IDLE =>
                        byte_cnt <= (others => '0');
                        if rx_sof = '1' then
                            state <= ST_SKIP;
                        end if;

                    -- Skip Ethernet + IPv4 headers
                    when ST_SKIP =>
                        if rx_eof = '1' then
                            state <= ST_IDLE;
                        elsif rx_valid = '1' then
                            byte_cnt <= byte_cnt + 1;
                            if byte_cnt = udp_start - 1 then
                                byte_cnt <= (others => '0');
                                if is_udp = '1' then
                                    state <= ST_UDP_HEADER;
                                else
                                    state <= ST_WAIT_EOF;
                                end if;
                            end if;
                        end if;

                    -- Parse 8-byte UDP header
                    when ST_UDP_HEADER =>
                        if rx_eof = '1' then
                            state <= ST_IDLE;
                        elsif rx_valid = '1' then
                            byte_cnt <= byte_cnt + 1;
                            case to_integer(byte_cnt) is
                                when 0 => src_port_r(15 downto 8) <= rx_byte;
                                when 1 => src_port_r(7 downto 0)  <= rx_byte;
                                when 2 => dst_port_r(15 downto 8) <= rx_byte;
                                when 3 => dst_port_r(7 downto 0)  <= rx_byte;
                                when 4 => length_r(15 downto 8)   <= rx_byte;
                                when 5 => length_r(7 downto 0)    <= rx_byte;
                                -- byte 6-7: checksum (ignore)
                                when 7 => state <= ST_WAIT_EOF;
                                when others => null;
                            end case;
                        end if;

                    when ST_WAIT_EOF =>
                        if rx_eof = '1' then
                            state <= ST_DONE;
                        end if;

                    when ST_DONE =>
                        udp_src_port <= src_port_r;
                        udp_dst_port <= dst_port_r;
                        udp_length   <= length_r;
                        parse_done   <= '1';
                        if is_udp = '1' then
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