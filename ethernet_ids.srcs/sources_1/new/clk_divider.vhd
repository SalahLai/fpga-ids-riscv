library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity clk_divider is 
    generic(
        CLK_FREQ_HZ:integer  := 50000000
    );
    port(
    clk  : in  std_logic;
    rst  : in  std_logic;
    tick : out std_logic
    );
    end clk_divider;
    
    
architecture rtl of clk_divider is 
    signal counter : unsigned(25 downto 0) := (others => '0');
begin
    process(clk)
    begin 
        if rising_edge(clk) then
            tick <= '0';
            if rst = '1' then 
                counter <= (others => '0');
            elsif counter = CLK_FREQ_HZ-1 then 
                counter<=(others=>'0');
                tick <= '1';
            else 
                counter <= counter +1;
            end if;
        end if;  
    end process;

end rtl;