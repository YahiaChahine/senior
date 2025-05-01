import matplotlib.pyplot as plt

x_samples  = []
y_lost_files  = [126, 235, 301, 85, 78, 78 , 77, 75, 79, 68, 66, 61, 57, 51, 50, 43, 40, 35, 28]

for i in range(len(y_lost_files)):
    x_samples.append(i+1)

min_val = min(y_lost_files)
max_val = max(y_lost_files)
min_pos = y_lost_files.index(min_val)
max_pos = y_lost_files.index(max_val)

# Create the plot
plt.figure(figsize=(8, 5))  # Adjust size if needed
plt.plot(x_samples, y_lost_files, marker='o', linestyle='-', color='b', label='Lost Files')

# Highlight min and max points
plt.scatter(x_samples[min_pos], min_val, color='g', s=100, label=f'Min: {min_val}')
plt.scatter(x_samples[max_pos], max_val, color='r', s=100, label=f'Max: {max_val}')

# Add labels and title
plt.xlabel('X-axis (Sample)')
plt.ylabel('Number of Lost Files')
plt.title('Lost Files Over Samples')
plt.legend()
plt.grid(True)

# Show the plot
plt.show()

