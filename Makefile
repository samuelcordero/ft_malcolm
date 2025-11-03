NAME = ft_malcolm
CFLAGS = -Wall -Wextra -Werror#-O2 #-g3 -fsanitize=address
CC = gcc
LIBFT = libft/libft.a
LD = -L libft -lft
INCLUDE = inc/ft_malcolm.h 
SRC = src/main.c
OBJ = $(SRC:.c=.o)
RM=/bin/rm -f

all: $(NAME)

$(LIBFT):
	@make bonus -C ./libft

$(MINILIBX):
	@make -C $(MINILIB_PATH)
	
$(NAME): $(LIBFT) $(MINILIBX) $(OBJ) $(INCLUDE) 
	$(CC) $(CFLAGS) $(OBJ) $(MINILIBX) $(LDFLAGS) -o $(NAME) $(LD)


%.o: %.c
	$(CC) $(CFLAGS) -Iinc -Ilibft -c -o $@ $<

clean:
	@make clean -C ./libft
	$(RM) $(OBJ)
	$(RM) $(OBJBONUS)

fclean: clean
	@make fclean -C ./libft
	$(RM) $(NAME)

re:: fclean
re:: all

asan:: CFLAGS += -fsanitize=address -g3
asan:: LDFLAGS += -fsanitize=address
asan:: re


.PHONY: all clean fclean re